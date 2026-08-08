#![warn(clippy::pedantic)]
#![doc = include_str!("../README.md")]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "resource-tracker only supports Linux; /proc and cgroup interfaces are Linux-specific."
);

mod collector;
mod config;
mod metrics;
mod output;
mod sentinel;
mod thread_util;

extern crate libc;

use std::io::{Write, BufWriter};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use collector::{
    CpuCollector,
    DiskCollector,
    GpuCollector,
    MemoryCollector,
    NetworkCollector,
    collect_host_info,
    spawn_cloud_discovery,
};
use config::{Config, OutputFormat};
use metrics::CloudInfo;
use metrics::Sample;
use sentinel::{
    BatchUploader,
    RunContext,
    SentinelClient,
    close_run,
    samples_to_csv,
    start_run,
};

// ---------------------------------------------------------------------------
// SIGTERM handler
// ---------------------------------------------------------------------------
//
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_: libc::c_int) {
    SIGTERM_RECEIVED.store(true, Ordering::Relaxed);
}

// Install SIGTERM and SIGINT handlers so the binary can flush before exiting.
// Both signals set the same flag and trigger the same graceful shutdown path.
//
fn setup_signal_handlers() {

    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_sigterm as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_sigterm as *const () as libc::sighandler_t,
        );
    }
}

struct ResourceTracker {

    config: Config,
    out_file: Option<std::io::BufWriter<std::fs::File>>,
    interval: Duration,

    // Collectors
    cpu: CpuCollector,
    memory: MemoryCollector,
    network: NetworkCollector,
    disk: DiskCollector,
    gpu: GpuCollector,

    // Cloud and host info
    host_info: metrics::HostInfo,
    cloud_info: Option<CloudInfo>,
    cloud_rx: Option<std::sync::mpsc::Receiver<CloudInfo>>,

    // Child process
    child: Option<std::process::Child>,

    // Sentinel state
    sentinel: Option<SentinelClient>,
    run_ctx_arc: Option<Arc<Mutex<RunContext>>>,
    sample_buffer: Option<Arc<Mutex<Vec<Sample>>>>,
    upload_shutdown_flag: Option<Arc<AtomicBool>>,
    upload_handle: Option<std::thread::JoinHandle<Vec<String>>>,

    // Sample tracking
    unflushed: Vec<Sample>,
    prev_loop_start: Option<Instant>,
}

impl ResourceTracker {

    fn new() -> Self {

        let config = Config::load();
        let out_file = Self::create_sink(&config);
        let interval = Duration::from_secs(config.interval_secs);

        let cpu = CpuCollector::new(config.pid);
        let memory = MemoryCollector::new();
        let network = NetworkCollector::new();
        let disk = DiskCollector::new(interval);
        let gpu = GpuCollector::new();

        // Collect static GPU info now so host discovery can derive GPU host fields.
        let initial_gpus = gpu.collect().unwrap_or_default();

        // Host discovery: fast, local, no I/O.
        let host_info = collect_host_info(&initial_gpus);

        // Warm-up: prime delta state in stateful collectors while cloud probes run
        let cloud_rx = spawn_cloud_discovery();
        let cloud_info = None;

        Self {
            config,
            out_file,
            interval,
            cpu,
            memory,
            network,
            disk,
            gpu,
            host_info,
            cloud_info,
            cloud_rx,
            child: None,
            sentinel: None,
            run_ctx_arc: None,
            sample_buffer: None,
            upload_shutdown_flag: None,
            upload_handle: None,
            unflushed: Vec::new(),
            prev_loop_start: None,
        }
    }

    fn warmup_collectors(&mut self) {

        let _ = self.cpu.collect();
        let _ = self.network.collect();
        let _ = self.disk.collect();
    }

    fn spawn_tracked_command(&mut self) {

        let Some((program, args)) = self.config.command.split_first() else {
            return;
        };

        match std::process::Command::new(program).args(args).spawn() {

            Ok(c) => {
                self.config.pid = Some(i32::try_from(c.id()).unwrap_or(i32::MAX));
                self.cpu.set_tracked_pid(self.config.pid);
                self.child = Some(c);
            }

            Err(e) => {
                eprintln!("error: failed to spawn {:?}: {e}", program);
                std::process::exit(1);
            }
        }
    }

    fn setup_sentinel(&mut self) {

        self.sentinel = SentinelClient::from_env();

        let Some(client) = &self.sentinel else {
            return;
        };

        // Bounded wait: give cloud discovery a chance to complete
        if self.cloud_info.is_none() {
            if let Some(ref rx) = self.cloud_rx {
                self.cloud_info = rx.recv_timeout(Duration::from_secs(3)).ok();
            }
        }

        let default_cloud = CloudInfo::default();
        let ctx = match start_run(
            &client.agent,
            &client.api_base,
            &client.token,
            &self.config.metadata,
            self.config.pid,
            &self.host_info,
            self.cloud_info.as_ref().unwrap_or(&default_cloud),
        ) {
            Err(e) => {
                eprintln!("warn: sentinel start_run failed: {e}; streaming disabled");
                return;
            }
            Ok(ctx) => ctx,
        };

        let ctx_arc = Arc::new(Mutex::new(ctx));
        let upload_interval = std::env::var("TRACKER_UPLOAD_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60u64);
        let (uploader, buf) = BatchUploader::new(upload_interval, self.config.interval_secs);
        let flag = uploader.shutdown_flag();
        let upload_handle = uploader.spawn(
            Arc::clone(&ctx_arc),
            SentinelClient::new_upload_agent(),
            client.api_base.clone(),
            client.token.clone(),
        );
        if upload_handle.is_none() {
            eprintln!(
                "warn: sentinel background upload disabled; samples will be flushed inline on exit"
            );
        }

        self.run_ctx_arc = Some(ctx_arc);
        self.sample_buffer = Some(buf);
        self.upload_shutdown_flag = Some(flag);
        self.upload_handle = upload_handle;
    }

    fn emit_csv_header(&mut self) {

        if self.config.format == OutputFormat::Csv {
            Self::emit_metric_line(&self.config, &mut self.out_file, output::csv::csv_header());
        }
    }

    fn renice_tracker(&self) {

        let Some(renice) = self.config.renice else {
            return;
        };

        let result = unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, renice)
        };
        if result == -1 {
            eprintln!("warn: failed to renice process, ignored");
        }
    }

    fn poll_cloud_info(&mut self) {

        if self.cloud_info.is_none()
            && let Some(ref rx) = self.cloud_rx
            && let Ok(info) = rx.try_recv()
        {
            self.cloud_info = Some(info);
        }
    }

    fn collect_sample(&mut self) -> Sample {

        let loop_start = Instant::now();

        let actual_interval_ms: Option<u64> = self.prev_loop_start
            .map(|p| u64::try_from((loop_start - p).as_millis()).unwrap_or(u64::MAX));

        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut sample = Sample {
            timestamp_secs,
            actual_interval_ms,
            job_name: self.config.metadata.job_name.clone(),
            tracked_pid: self.config.pid,
            cpu: self.cpu.collect().unwrap_or_default(),
            memory: self.memory.collect().unwrap_or_default(),
            network: self.network.collect().unwrap_or_default(),
            disk: self.disk.collect().unwrap_or_default(),
            gpu: self.gpu.collect().unwrap_or_default(),
        };

        // Augment with per-process GPU stats.
        let (vram_mib, gpu_usage, gpu_utilized) =
            if self.config.pid.is_some() && !sample.cpu.process_tree_pids.is_empty() {
                let pids_u32: Vec<u32> = sample
                    .cpu
                    .process_tree_pids
                    .iter()
                    .filter_map(|&p| u32::try_from(p).ok())
                    .collect();
                self.gpu.process_gpu_info(&pids_u32, self.interval)
            } else {
                self.gpu.all_gpu_process_info(self.interval)
            };
        sample.cpu.process_gpu_vram_mib = vram_mib;
        sample.cpu.process_gpu_usage = gpu_usage;
        sample.cpu.process_gpu_utilized = gpu_utilized;

        self.prev_loop_start = Some(loop_start);

        sample
    }

    fn emit_sample(&mut self, sample: &Sample) {

        match self.config.format {

            OutputFormat::Json => match serde_json::to_value(sample) {
                Ok(mut v) => {
                    v[format!("{}-version", env!("CARGO_PKG_NAME"))] =
                        serde_json::Value::String(env!("CARGO_PKG_VERSION").to_string());
                    Self::emit_metric_line(
                        &self.config,
                        &mut self.out_file,
                        &v.to_string(),
                    );
                }
                Err(e) => eprintln!("warn: json serialize error: {e}"),
            },

            OutputFormat::Csv => {
                Self::emit_metric_line(
                    &self.config,
                    &mut self.out_file,
                    &output::csv::sample_to_csv_row(sample, self.config.interval_secs),
                );
            }
        }
    }

    fn buffer_sample(&mut self, sample: Sample) {

        // Push to sentinel buffer (if streaming is active).
        if let Some(ref buf) = self.sample_buffer {
            buf.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(sample.clone());
        }
        self.unflushed.push(sample);
    }

    fn check_child_exit(&mut self) -> Option<i32> {

        let child = self.child.as_mut()?;

        match child.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(1)),
            Ok(None) => None,
            Err(e) => {
                eprintln!("warn: error checking child status: {e}");
                None
            }
        }
    }

    fn check_signal(&self) -> bool {
        SIGTERM_RECEIVED.load(Ordering::Relaxed)
    }

    fn sleep_until_next_interval(&self, loop_start: Instant) {

        let elapsed = loop_start.elapsed();
        if let Some(remaining) = self.interval.checked_sub(elapsed) {
            std::thread::sleep(remaining);
        }
    }

    fn shutdown(&mut self, exit_code: i32) -> ! {

        // Take ownership of fields that need to be moved
        let sentinel = self.sentinel.take();
        let run_ctx = self.run_ctx_arc.take();
        let shutdown_flag = self.upload_shutdown_flag.take();
        let upload_handle = self.upload_handle.take();
        let remaining = std::mem::take(&mut self.unflushed);

        Self::graceful_shutdown(
            exit_code,
            sentinel.as_ref(),
            run_ctx,
            shutdown_flag,
            upload_handle,
            remaining,
            self.config.interval_secs,
        );
    }

    fn run(mut self) -> ! {

        self.warmup_collectors();
        std::thread::sleep(self.interval);

        self.spawn_tracked_command();
        self.setup_sentinel();
        self.emit_csv_header();
        self.renice_tracker();

        // Main sampling loop
        loop {
            self.poll_cloud_info();
            let loop_start = Instant::now();

            let sample = self.collect_sample();
            self.emit_sample(&sample);
            self.buffer_sample(sample);

            if let Some(code) = self.check_child_exit() {
                self.shutdown(code);
            }
            if self.check_signal() {
                self.shutdown(0);
            }

            self.sleep_until_next_interval(loop_start);
        }
    }


    // -----------------------------------------------------------------------
    // Output sink: stdout (default), file (--output), or suppressed (--quiet).
    // Warnings and errors always go to stderr via eprintln! regardless.
    // -----------------------------------------------------------------------
    //
    fn create_sink(config: &Config) -> Option<BufWriter<File>> {

        if config.quiet {
            return None;
        }

        match config.output_file.as_deref() {
            Some(path) => File::create(path).map(BufWriter::new).ok(),
            None => None,
        }
    }

    // ---------------------------------------------------------------------------
    // Graceful shutdown
    // ---------------------------------------------------------------------------
    //
    // Flush remaining samples, close the Sentinel run, then exit.
    //
    // Called on both shell-wrapper child exit and SIGTERM.  Replaces the former
    // bare `std::process::exit()` calls so the upload thread always gets a chance
    // to flush.
    //
    fn graceful_shutdown(
        exit_code: i32,
        sentinel: Option<&SentinelClient>,
        run_ctx: Option<Arc<Mutex<RunContext>>>,
        shutdown_flag: Option<Arc<AtomicBool>>,
        upload_handle: Option<std::thread::JoinHandle<Vec<String>>>,
        remaining: Vec<Sample>,
        interval_secs: u64,
    ) -> ! {

        if let (Some(client), Some(ctx_arc), Some(flag), Some(handle)) =
            (sentinel, run_ctx, shutdown_flag, upload_handle)
        {
            // Signal the upload thread to flush its buffer to S3, then wait for it.
            // The thread performs one final S3 upload of any remaining buffered samples
            // before it exits, and returns the list of all successfully uploaded URIs.
            flag.store(true, Ordering::Relaxed);
            let uploaded_uris = handle.join().unwrap_or_default();

            // Route selection:
            //   S3 route   -- at least one batch was uploaded; uploaded_uris is non-empty.
            //                 The final flush is already included in uploaded_uris.
            //   Inline route -- no S3 uploads (short run or all S3 failures); send all
            //                   collected samples as a raw CSV string.
            let remaining_csv = if uploaded_uris.is_empty() && !remaining.is_empty() {
                Some(samples_to_csv(&remaining, interval_secs))
            } else {
                None
            };

            let ctx = ctx_arc.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = close_run(
                &client.agent,
                &client.api_base,
                &client.token,
                &ctx,
                Some(exit_code),
                remaining_csv,
                &uploaded_uris,
            ) {
                eprintln!("warn: sentinel close_run failed: {e}");
            }
        }

        std::process::exit(exit_code);
    }

    // Emit one line of metric output to the selected sink.
    // quiet=true  -> no-op
    // output_file -> write to file and flush (so `tail -f` works)
    // default     -> eprintln! to stderr (keeps stdout clean for the tracked app)
    //
    fn emit_metric_line(config: &Config, out_file: &mut Option<BufWriter<File>>, msg: &str) {

        if config.quiet {
            return;
        }

        match out_file {
            Some(writer) => {
                let _ = writeln!(writer, "{msg}");
                let _ = writer.flush();
            }
            None => eprintln!("{msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
//
fn main() {
    setup_signal_handlers();
    let tracker = ResourceTracker::new();
    tracker.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that SIGINT sets SIGTERM_RECEIVED, triggering the same graceful
    /// shutdown path as SIGTERM.  The test installs the handler, resets the
    /// flag, raises SIGINT, then asserts the flag is true.
    #[test]
    fn test_sigint_sets_shutdown_flag() {
        // Reset in case a previous test left the flag set.
        SIGTERM_RECEIVED.store(false, Ordering::SeqCst);

        // Install the handler for SIGINT (mirrors what main() does).
        unsafe {
            libc::signal(
                libc::SIGINT,
                handle_sigterm as *const () as libc::sighandler_t,
            );
        }

        // Raise SIGINT on the current process.
        unsafe {
            libc::raise(libc::SIGINT);
        }

        assert!(
            SIGTERM_RECEIVED.load(Ordering::SeqCst),
            "SIGTERM_RECEIVED flag must be true after SIGINT"
        );

        // Clean up: reset the flag and restore the default SIGINT disposition
        // so this does not interfere with other tests.
        SIGTERM_RECEIVED.store(false, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
    }
}
