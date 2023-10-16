use clap::Parser;
use itertools::Itertools;
use nix::sys::stat;
use nix::unistd;
use palette::{FromColor, Okhsl, OklabHue, Srgb};
use plotters::prelude::*;
use smol::channel::Sender;
use smol::fs::File;
use smol::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use smol::process::Command;
use smol::stream::StreamExt;
use smol::Timer;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tempfile::tempdir;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum EventKind {
    Perf,
    CpuUsage,
    MemoryUsage,
    GlobalMemoryUsage,
    Temperature,
    DiskRead,
    DiskWrite,
    NetworkIn,
    NetworkOut,
}

#[derive(Debug, Clone)]
struct Event {
    instant: Instant,
    kind: EventKind,
    pid: u32,
    label: Option<String>,
    value: f32,
}

#[derive(Debug, Clone, Copy)]
struct ProcessStat {
    ppid: u32,
    utime: u32,
    stime: u32,
}

fn get_process_stat(pid: u32, tid: u32) -> Result<ProcessStat> {
    let buf = fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat"))?;

    let res = (|| {
        let pos = buf.find(')')?;
        let mut fields = buf[pos + 1..].split_ascii_whitespace();
        fields.next()?;
        let ppid = fields.next()?.parse().ok()?;
        for _ in 0..9 {
            fields.next()?;
        }
        let utime = fields.next()?.parse().ok()?;
        let stime = fields.next()?.parse().ok()?;
        Some(ProcessStat { ppid, utime, stime })
    })();

    res.ok_or_else(|| anyhow!("invalid proc format"))
}

#[derive(Debug, Clone, Copy)]
struct MemoryRegion {
    size: u64,
    offset: u64,
    inode: u32,
    flags: u8,
}

const FLAG_PRIVATE: u8 = 8;
const FLAG_READ: u8 = 4;
const FLAG_WRITE: u8 = 2;
const FLAG_EXECUTE: u8 = 1;

fn get_process_maps(pid: u32) -> Result<Vec<MemoryRegion>> {
    let buf = fs::read_to_string(format!("/proc/{pid}/maps"))?;

    let mut regions = Vec::new();
    for line in buf.lines() {
        let res = (|| {
            let mut fields = line.split(' ');
            let range = fields.next()?;
            let size = {
                let mut fields = range.split('-');
                let start = u64::from_str_radix(fields.next()?, 16).ok()?;
                let end = u64::from_str_radix(fields.next()?, 16).ok()?;
                end - start
            };
            let flags = fields.next()?;
            let flags = {
                let r = u8::from(flags.contains('r'));
                let w = u8::from(flags.contains('w'));
                let x = u8::from(flags.contains('x'));
                let p = u8::from(flags.contains('p'));
                p * 8 + r * 4 + w * 2 + x
            };
            let offset = fields.next()?.parse::<u64>().ok()?;
            fields.next()?;
            let inode = fields.next()?.parse::<u32>().ok()?;
            Some(MemoryRegion {
                size,
                offset,
                inode,
                flags,
            })
        })();

        if let Some(res) = res {
            regions.push(res);
        }
    }

    Ok(regions)
}

fn get_cpu_time() -> Result<f64> {
    let buf = fs::read_to_string(format!("/proc/stat"))?;

    let mut time = 0;
    let mut num_cpus = 0;

    for line in buf.lines() {
        if line.starts_with("cpu ") {
            let _ = (|| {
                let mut fields = line.split_ascii_whitespace();

                fields.next()?;
                let user: u64 = fields.next()?.parse().ok()?;
                let nice: u64 = fields.next()?.parse().ok()?;
                let system: u64 = fields.next()?.parse().ok()?;
                let idle: u64 = fields.next()?.parse().ok()?;
                let iowait: u64 = fields.next()?.parse().ok()?;
                let irq: u64 = fields.next()?.parse().ok()?;
                let softirq: u64 = fields.next()?.parse().ok()?;

                time = user + nice + system + idle + iowait + irq + softirq;

                Some(())
            })();
        } else if line.starts_with("cpu") {
            num_cpus += 1;
        } else {
            break;
        }
    }

    Ok(time as f64 / (num_cpus as f64))
}

fn get_process_parent(pid: u32) -> Result<u32> {
    Ok(get_process_stat(pid, pid)?.ppid)
}

fn get_process_tree(root: u32, include_tasks: bool) -> Result<Vec<(u32, u32)>> {
    let mut visited = Vec::new();
    let mut queued = Vec::new();

    queued.push(root);

    while let Some(pid) = queued.pop() {
        let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task/")) else {
            continue;
        };

        for entry in tasks {
            let entry = entry?;
            let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };

            if include_tasks || pid == tid {
                visited.push((pid, tid));
            }

            let mut path = entry.path();
            path.push("children");
            let buf = fs::read_to_string(path)?;
            let children = buf.split(' ').flat_map(|v| v.parse::<u32>().ok());
            queued.extend(children);
        }
    }

    Ok(visited)
}

fn get_process_network_usage(pid: u32, tid: u32, iface: &str) -> Result<(u64, u64)> {
    let buf = fs::read_to_string(format!("/proc/{pid}/task/{tid}/net/dev"))?;

    for line in buf.lines() {
        let line = line.trim();
        if !line.starts_with(iface) {
            continue;
        }

        let res = (|| {
            let mut fields = line.split_ascii_whitespace();
            fields.next()?;
            let rx = fields.next()?.parse::<u64>().ok()?;
            for _ in 0..7 {
                fields.next()?;
            }
            let tx = fields.next()?.parse::<u64>().ok()?;
            Some((tx, rx))
        })();

        let Some((tx, rx)) = res else { continue };
        return Ok((tx, rx));
    }

    Ok((0, 0))
}

fn get_process_memory_usage(pid: u32) -> Result<u64> {
    let mut usage = 0;

    for (pid, _) in get_process_tree(pid, false)? {
        for map in get_process_maps(pid)? {
            if map.flags & FLAG_PRIVATE > 0 && map.flags & FLAG_WRITE > 0 {
                usage += map.size;
            }
        }
    }

    Ok(usage)
}

#[derive(Debug, Clone, Copy, Default)]
struct MemInfo {
    total: u64,
    used: u64,
    free: u64,
    available: u64,
    buffers: u64,
    cached: u64,
}

fn get_memory_info() -> Result<MemInfo> {
    let buf = fs::read_to_string(format!("/proc/meminfo"))?;

    let mut info = MemInfo::default();

    for line in buf.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(field) = fields.next() else {
            continue;
        };

        let Some(value) = fields.next().and_then(|v| v.parse::<u64>().ok()) else {
            continue;
        };

        match field {
            "MemTotal:" => info.total = value,
            "MemFree:" => info.free = value,
            "MemAvailable:" => info.available = value,
            "Buffers:" => info.buffers = value,
            "Cached:" => info.cached = value,
            _ => {}
        }
    }

    info.used = info.total - info.free;

    Ok(info)
}

async fn sample_cpu_usage(sender: Sender<Event>, interval: Duration, root_pid: u32) -> Result<()> {
    let mut last_cpu_time = None;
    let mut last_task_times = HashMap::new();

    while PathBuf::from(format!("/proc/{root_pid}/")).exists() {
        let instant = Instant::now();
        let cpu_time = get_cpu_time()?;

        for (pid, tid) in get_process_tree(root_pid, true)? {
            let stat = get_process_stat(pid, tid)?;
            let task_time = stat.utime + stat.stime;

            if let (Some(last_cpu_time), Some(&last_task_time)) =
                (last_cpu_time, last_task_times.get(&tid))
            {
                let cpu_usage = (task_time.saturating_sub(last_task_time) as f32)
                    / ((cpu_time - last_cpu_time) as f32)
                    * 100.0;

                let event = Event {
                    instant,
                    kind: EventKind::CpuUsage,
                    pid: tid,
                    label: Some(format!("{root_pid}")),
                    value: cpu_usage,
                };

                let _ = sender.send(event).await;
            }

            last_task_times.insert(tid, task_time);
        }

        last_cpu_time = Some(cpu_time);

        Timer::at(instant + interval).await;
    }

    Ok(())
}

async fn sample_memory_usage(sender: Sender<Event>, interval: Duration, pid: u32) -> Result<()> {
    while PathBuf::from(format!("/proc/{pid}/")).exists() {
        let instant = Instant::now();

        let usage = get_process_memory_usage(pid)?;
        let event = Event {
            instant,
            kind: EventKind::MemoryUsage,
            pid: 0,
            label: Some(format!("{pid}")),
            value: usage as f32,
        };

        let _ = sender.send(event).await;

        Timer::at(instant + interval).await;
    }

    Ok(())
}

async fn sample_global_memory_usage(sender: Sender<Event>, interval: Duration) -> Result<()> {
    loop {
        let instant = Instant::now();
        let info = get_memory_info()?;

        let values = [
            ("Total", info.total),
            ("Used", info.used),
            ("Free", info.free),
            ("Available", info.available),
            ("Buffers", info.buffers),
            ("Cached", info.cached),
        ];

        for (name, value) in values {
            let event = Event {
                instant,
                kind: EventKind::GlobalMemoryUsage,
                pid: 0,
                label: Some(name.into()),
                value: value as f32,
            };

            let _ = sender.send(event).await;
        }

        Timer::at(instant + interval).await;
    }
}

async fn sample_temperature(sender: Sender<Event>, interval: Duration) -> Result<()> {
    loop {
        let instant = Instant::now();
        let child = Command::new("sensors")
            .arg("-jA")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut stdout = child.stdout.ok_or_else(|| anyhow!("no stdout handle"))?;
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).await?;

        let entries: HashMap<String, HashMap<String, HashMap<String, f32>>> =
            serde_json::from_slice(&buf)?;
        for (entry_name, entry) in &entries {
            for (group_name, group) in entry {
                for (value_name, &value) in group {
                    if value_name.starts_with("temp") && value_name.ends_with("input") {
                        let event = Event {
                            instant,
                            kind: EventKind::Temperature,
                            pid: 0,
                            label: Some(format!("{entry_name}.{group_name}")),
                            value,
                        };

                        let _ = sender.send(event).await;
                    }
                }
            }
        }

        Timer::at(instant + interval).await;
    }
}

async fn sample_disk_usage(
    sender: Sender<Event>,
    interval: Duration,
    root_pids: Vec<u32>,
) -> Result<()> {
    let child = Command::new("iotop")
        .args(["-tPkoqqq"])
        .arg("-d")
        .arg(format!("{:.3}", interval.as_secs_f32()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .map(BufReader::new)
        .ok_or_else(|| anyhow!("no stdout handle"))?;

    let mut lines = stdout.lines();
    while let Some(line) = lines.next().await {
        let line = line?;
        let instant = Instant::now();

        let res = (|| {
            let mut split = line.split_ascii_whitespace();
            let _time = split.next()?;
            let pid = split.next()?.parse::<u32>().ok()?;
            split.next()?;
            split.next()?;
            let disk_read = split.next()?.parse::<f32>().ok()?;
            split.next()?;
            let disk_write = split.next()?.parse::<f32>().ok()?;
            Some((pid, disk_read, disk_write))
        })();

        let Some((pid, disk_read, disk_write)) = res else {
            continue;
        };

        for &root_pid in &root_pids {
            let mut cur_pid = pid;
            while cur_pid != root_pid {
                if let Ok(parent) = get_process_parent(cur_pid) {
                    cur_pid = parent;
                } else {
                    break;
                }
            }

            if cur_pid != root_pid {
                continue;
            }

            let event = Event {
                instant,
                kind: EventKind::DiskRead,
                pid,
                label: Some(format!("{root_pid}")),
                value: disk_read * 1024.0,
            };

            let _ = sender.send(event).await;

            let event = Event {
                instant,
                kind: EventKind::DiskWrite,
                pid,
                label: Some(format!("{root_pid}")),
                value: disk_write * 1024.0,
            };

            let _ = sender.send(event).await;
        }
    }

    Ok(())
}

async fn sample_network_usage(
    sender: Sender<Event>,
    interval: Duration,
    root_pid: u32,
    iface: String,
) -> Result<()> {
    let mut last_instant = Instant::now();
    let mut last_task_tx_rx = HashMap::new();

    while PathBuf::from(format!("/proc/{root_pid}/")).exists() {
        let instant = Instant::now();
        let elapsed = instant.saturating_duration_since(last_instant);
        last_instant = instant;

        for (pid, tid) in get_process_tree(root_pid, true)? {
            let (tx, rx) = get_process_network_usage(pid, tid, &iface)?;

            if let Some(&(last_tx, last_rx)) = last_task_tx_rx.get(&tid) {
                let net_in = (rx.saturating_sub(last_rx) as f64 / elapsed.as_secs_f64()) as f32;
                let net_out = (tx.saturating_sub(last_tx) as f64 / elapsed.as_secs_f64()) as f32;

                let event = Event {
                    instant,
                    kind: EventKind::NetworkIn,
                    pid,
                    label: Some(format!("{root_pid}")),
                    value: net_in,
                };

                let _ = sender.send(event).await;

                let event = Event {
                    instant,
                    kind: EventKind::NetworkOut,
                    pid,
                    label: Some(format!("{root_pid}")),
                    value: net_out,
                };

                let _ = sender.send(event).await;
            }

            last_task_tx_rx.insert(tid, (tx, rx));
        }

        Timer::at(instant + interval).await;
    }

    Ok(())
}

async fn sample_perf(sender: Sender<Event>, fifo: PathBuf) -> Result<()> {
    let file = BufReader::new(File::open(fifo).await?);
    let mut lines = file.lines();

    while let Some(line) = lines.next().await {
        let line = line?;
        let res = (|| {
            let mut parts = line.split(';');
            parts.next()?;
            let value = parts.next()?.parse::<f32>().ok()?;
            parts.next()?;
            let label = parts.next()?.to_string();
            Some((value, label))
        })();

        let Some((value, label)) = res else {
            continue;
        };

        let event = Event {
            instant: Instant::now(),
            kind: EventKind::Perf,
            pid: 0,
            label: Some(label),
            value,
        };

        let _ = sender.send(event).await;
    }

    Ok(())
}

fn preprocess_data(
    events: &[&Event],
    aggregate: bool,
    start_instant: Instant,
) -> (f32, Vec<Vec<(f32, f32)>>) {
    let max_sum = events
        .iter()
        .group_by(|e| e.instant)
        .into_iter()
        .map(|(_, group)| group.map(|e| e.value).sum::<f32>())
        .fold(0.0, f32::max);

    let order = events
        .iter()
        .sorted_by_key(|e| e.pid)
        .group_by(|e| e.pid)
        .into_iter()
        .map(|(pid, group)| (pid, group.map(|e| e.value).sum::<f32>()))
        .sorted_by(|(_, a), (_, b)| f32::total_cmp(&b, &a))
        .map(|v| v.0)
        .collect::<Vec<_>>();

    let mut series: Vec<Vec<(f32, f32)>> = vec![vec![]; order.len()];

    events
        .iter()
        .group_by(|e| e.instant)
        .into_iter()
        .for_each(|(instant, group)| {
            let group = group.collect::<Vec<_>>();
            let x_value = instant
                .saturating_duration_since(start_instant)
                .as_secs_f32();
            for (i, &cur_group) in order.iter().enumerate() {
                let mut y_value = group
                    .iter()
                    .filter(|e| e.pid == cur_group)
                    .map(|e| e.value)
                    .next()
                    .unwrap_or(0.0);
                if i > 0 {
                    y_value += series[i - 1].last().unwrap().1;
                }
                series[i].push((x_value, y_value));
            }
        });

    if aggregate {
        let sum = series.iter().cloned().reduce(|a, b| {
            a.iter()
                .zip(b)
                .map(|(a, b)| (a.0, a.1 + b.1))
                .collect::<Vec<_>>()
        });

        if let Some(sum) = sum {
            series = vec![sum];
        }
    }

    (max_sum, series)
}

fn plot(
    events: &[Event],
    aggregate: bool,
    start_instant: Instant,
    elapsed: f32,
    filter_kind: EventKind,
    title: &str,
    output: &Path,
) -> Result<()> {
    let by_label = events
        .iter()
        .filter(|e| e.kind == filter_kind)
        .sorted_by_key(|e| &e.label)
        .group_by(|e| &e.label)
        .into_iter()
        .map(|(label, events)| {
            let events = events.collect::<Vec<_>>();
            let (max_value, series) = preprocess_data(&events, aggregate, start_instant);
            (label.as_ref(), max_value, series)
        })
        .collect::<Vec<_>>();

    let mut max_value = by_label.iter().map(|v| v.1).fold(0.0, f32::max);

    if max_value == 0.0 {
        max_value = 1.0;
    }

    let root = SVGBackend::new(output, (640, 480)).into_drawing_area();
    root.fill(&RGBColor(255, 255, 255))?;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 20).into_font())
        .margin(15)
        .x_label_area_size(20)
        .y_label_area_size(75)
        .build_cartesian_2d(0.0..elapsed, 0.0..max_value)?;

    let colors = by_label
        .iter()
        .enumerate()
        .map(|(i, (_, _, series))| {
            (0..series.len())
                .map(|j| {
                    let hue = OklabHue::from_degrees(
                        150.0
                            + (i as f32) / (by_label.len() as f32) * 300.0
                            + (j as f32) / (series.len() as f32) * 150.0,
                    );

                    let a = Srgb::from_color(Okhsl::new(hue, 0.8, 0.5));

                    let b = Srgb::from_color(Okhsl::new(hue, 0.8, 0.8));

                    let a = a.into_format::<u8>();
                    let b = b.into_format::<u8>();
                    (
                        RGBColor(a.red, a.green, a.blue),
                        RGBColor(b.red, b.green, b.blue),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    if by_label.len() == 1 {
        for ((_, _, series), colors) in by_label.iter().zip(&colors) {
            for (series, (_, area_color)) in series.iter().zip(colors).rev() {
                chart.draw_series(AreaSeries::new(series.iter().copied(), 0.0, area_color))?;
            }
        }
    }

    chart.configure_mesh().draw()?;
    let mut has_labels = false;

    for ((label, _, series), colors) in by_label.iter().zip(&colors) {
        for (series, &(border_color, _)) in series.iter().zip(colors).rev() {
            let series =
                chart.draw_series(LineSeries::new(series.iter().copied(), &border_color))?;
            if let &Some(label) = label {
                series.label(label).legend(move |(x, y)| {
                    PathElement::new(vec![(x, y), (x + 20, y)], &border_color)
                });
                has_labels = true;
            }
        }
    }

    if has_labels {
        chart
            .configure_series_labels()
            .border_style(&BLACK.mix(0.8))
            .background_style(&WHITE.mix(0.5))
            .draw()?;
    }

    root.present()?;
    println!("Saved {}", output.display());

    Ok(())
}

fn spawn_task(f: impl Future<Output = Result<()>> + Send + Sync + 'static) {
    smol::spawn(async move {
        if let Err(e) = f.await {
            eprintln!("Error: {:?}", e);
        }
    })
    .detach();
}

#[derive(Debug, clap::Parser)]
#[command(author, version)]
struct Args {
    /// Time in seconds between recorded samples
    #[arg(short, long, default_value = "0.5")]
    interval: f32,
    /// CPU utilization
    #[arg(short, long)]
    cpu: bool,
    /// Memory usage
    #[arg(short, long)]
    memory: bool,
    /// Memory usage (global)
    #[arg(short = 'M', long)]
    global_memory: bool,
    /// Temperature sensors (requiers sensors)
    #[arg(short, long)]
    temperature: bool,
    /// Disk R/W (requires iotop)
    #[arg(short, long)]
    disk: bool,
    /// Network I/O
    #[arg(short, long)]
    network: bool,
    /// Network interface
    #[arg(short = 'N', long, default_value = "lo")]
    net_iface: String,
    /// List of pids to sample
    #[arg(short = 'P', long, use_value_delimiter = true)]
    pids: Option<Vec<u32>>,
    /// List of perf events to record (requires perf)
    #[arg(short, long, conflicts_with = "pids")]
    perf: Option<String>,
    /// Program to run
    #[arg(required_unless_present = "pids")]
    program: Option<OsString>,
    /// Arguments passed to the program
    args: Vec<OsString>,
}

async fn async_main() -> Result<()> {
    let args = Args::parse();

    let interval = Duration::from_secs_f32(args.interval);

    let tmp_dir = tempdir()?;
    let fifo = args
        .perf
        .is_some()
        .then(|| {
            let fifo_path = tmp_dir.path().join("perf.pipe");
            unistd::mkfifo(&fifo_path, stat::Mode::S_IRWXU).map(|_| fifo_path)
        })
        .transpose()?;

    let (pids, child) = if let Some(program) = args.program {
        let child = if let (Some(perf), Some(fifo)) = (&args.perf, &fifo) {
            Command::new("perf")
                .args(["stat", "-e", perf, "-x", ";", "-I"])
                .arg(format!("{}", interval.as_millis().max(10)))
                .arg("-o")
                .arg(fifo)
                .arg("--")
                .arg(program)
                .args(args.args)
                .spawn()?
        } else {
            Command::new(program).args(args.args).spawn()?
        };

        (vec![child.id()], Some(child))
    } else {
        let pids = args.pids.unwrap();
        (pids, None)
    };

    let start_instant = Instant::now();

    let (sender, receiver) = smol::channel::unbounded();

    if args.cpu {
        for &pid in &pids {
            spawn_task(sample_cpu_usage(sender.clone(), interval, pid));
        }
    }

    if args.memory {
        for &pid in &pids {
            spawn_task(sample_memory_usage(sender.clone(), interval, pid));
        }
    }

    if args.global_memory {
        spawn_task(sample_global_memory_usage(sender.clone(), interval));
    }

    if args.temperature {
        spawn_task(sample_temperature(sender.clone(), interval));
    }

    if args.disk {
        spawn_task(sample_disk_usage(sender.clone(), interval, pids.clone()));
    }

    if args.network {
        for &pid in &pids {
            spawn_task(sample_network_usage(
                sender.clone(),
                interval,
                pid,
                args.net_iface.clone(),
            ));
        }
    }

    if let Some(fifo) = fifo {
        spawn_task(sample_perf(sender.clone(), fifo));
    }

    if let Some(mut child) = child {
        child.status().await?;
    } else {
        while pids
            .iter()
            .any(|pid| PathBuf::from(format!("/proc/{pid}/")).exists())
        {
            Timer::after(interval).await;
        }
    }

    let end_instant = Instant::now();
    let elapsed = end_instant
        .saturating_duration_since(start_instant)
        .as_secs_f32();

    sender.close();

    let mut events = Vec::new();
    while let Ok(event) = receiver.recv().await {
        events.push(event);
    }

    let kinds = [
        (
            args.perf.is_some(),
            EventKind::Perf,
            "plots/perf.svg",
            "Perf events",
        ),
        (
            args.cpu,
            EventKind::CpuUsage,
            "plots/cpu_usage.svg",
            "CPU utilization",
        ),
        (
            args.memory,
            EventKind::MemoryUsage,
            "plots/memory_usage.svg",
            "Memory usage",
        ),
        (
            args.global_memory,
            EventKind::GlobalMemoryUsage,
            "plots/global_memory_usage.svg",
            "Memory usage (Global)",
        ),
        (
            args.temperature,
            EventKind::Temperature,
            "plots/temperature.svg",
            "Temperature",
        ),
        (
            args.disk,
            EventKind::DiskRead,
            "plots/disk_read.svg",
            "Disk read",
        ),
        (
            args.disk,
            EventKind::DiskWrite,
            "plots/disk_write.svg",
            "Disk write",
        ),
        (
            args.network,
            EventKind::NetworkIn,
            "plots/net_in.svg",
            "Network in",
        ),
        (
            args.network,
            EventKind::NetworkOut,
            "plots/net_out.svg",
            "Network out",
        ),
    ];

    for (cond, kind, output, title) in kinds {
        if cond {
            let output = output.as_ref();
            plot(
                &events,
                pids.len() > 1,
                start_instant,
                elapsed,
                kind,
                title,
                output,
            )?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    smol::block_on(async_main())
}
