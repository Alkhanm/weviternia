use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use chrono::{DateTime, Local};
use regex::Regex;
use serde::Serialize;
// Importa lib compartilhada
use traffic_utils::{get_current_epoch, load_map_from_file, load_set_from_file};

const FLUSH_INTERVAL: f64 = 5.0;

struct Config {
    iface: String,
    lan_regex: Regex,
    json_output: String,
    ignore_clients_path: String,
    hosts_map_path: String,
}

struct ClientData {
    bytes_in: u64,
    bytes_out: u64,
    bytes_total: u64,
    last_seen_any: f64,
    last_seen_out: f64,
}

#[derive(Serialize)]
struct ClientJsonStats {
    bytes_in: u64, bytes_out: u64, bytes_total: u64,
    mb_in: f64, mb_out: f64, mb_total: f64,
    #[serde(skip_serializing_if = "Option::is_none")] last_seen_any: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] last_seen_out: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] hostname: Option<String>,
}

#[derive(Serialize)]
struct JsonRoot { updated_at: String, clients: HashMap<String, ClientJsonStats> }

fn main() {
    let config = load_config();
    if let Some(parent) = std::path::Path::new(&config.json_output).parent() {
        let _ = fs::create_dir_all(parent);
    }
    println!("[bytes] Monitorando tráfego JSON: {}", config.json_output);

    let mut stats_map: HashMap<String, ClientData> = HashMap::new();
    let mut ignore_clients: HashSet<String> = HashSet::new();
    let mut hosts_map: HashMap<String, String> = HashMap::new();
    let mut last_flush = get_current_epoch();
    let mut last_reload = 0.0;

    let tcpdump_line_re = Regex::new(r" IP (\S+) > (\S+): .*? (\d+)$").unwrap();

    let mut child = Command::new("tcpdump")
        .args(&["-i", &config.iface, "-n", "-tt", "-q", "-l", "ip"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn().expect("Falha tcpdump");
    
    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    for line_res in reader.lines() {
        let line = match line_res { Ok(l) => l, Err(_) => break };
        let now = get_current_epoch();

        if now - last_reload >= 10.0 {
            ignore_clients = load_set_from_file(&config.ignore_clients_path);
            hosts_map = load_map_from_file(&config.hosts_map_path);
            last_reload = now;
        }

        if let Some(caps) = tcpdump_line_re.captures(&line) {
            let size: u64 = caps[3].parse().unwrap_or(0);
            if size == 0 { continue; }
            let src_ip = strip_port(&caps[1]);
            let dst_ip = strip_port(&caps[2]);
            
            let is_src = config.lan_regex.is_match(&src_ip);
            let is_dst = config.lan_regex.is_match(&dst_ip);

            if (is_src && ignore_clients.contains(&src_ip)) || (is_dst && ignore_clients.contains(&dst_ip)) { continue; }

            if is_src {
                let e = stats_map.entry(src_ip.clone()).or_insert(ClientData{bytes_in:0,bytes_out:0,bytes_total:0,last_seen_any:0.0,last_seen_out:0.0});
                e.bytes_out += size; e.bytes_total += size; e.last_seen_any = now; e.last_seen_out = now;
            }
            if is_dst {
                let e = stats_map.entry(dst_ip.clone()).or_insert(ClientData{bytes_in:0,bytes_out:0,bytes_total:0,last_seen_any:0.0,last_seen_out:0.0});
                e.bytes_in += size; e.bytes_total += size; e.last_seen_any = now;
            }
        }

        if now - last_flush >= FLUSH_INTERVAL {
            save_json(&config.json_output, &stats_map, &hosts_map);
            last_flush = now;
        }
    }
}

fn load_config() -> Config {
    Config {
        iface: env::var("IFACE").unwrap_or_else(|_| "enx00e04c68054d".to_string()),
        lan_regex: Regex::new(&env::var("LAN_REGEX").unwrap_or_else(|_| "^192\\.168\\.1\\.".to_string())).unwrap(),
        json_output: env::var("OUTFILE").unwrap_or_else(|_| "/var/log/traffic-domains/traffic-bytes.json".to_string()),
        ignore_clients_path: env::var("IGNORE_CLIENTS_FILE").unwrap_or_else(|_| "/etc/traffic-monitor/ignore-clients.txt".to_string()),
        hosts_map_path: env::var("HOSTS_MAP_FILE").unwrap_or_else(|_| "/etc/traffic-monitor/lan-hosts.txt".to_string()),
    }
}

fn strip_port(s: &str) -> String {
    let clean = s.trim_end_matches(':');
    if let Some(idx) = clean.rfind('.') { return clean[..idx].to_string(); }
    clean.to_string()
}

fn format_ts(ts: f64) -> String {
    if ts == 0.0 { return "".to_string(); }
    let dt = DateTime::from_timestamp(ts as i64, 0).unwrap_or_default();
    let local: DateTime<Local> = DateTime::from(dt);
    local.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn save_json(path: &str, stats: &HashMap<String, ClientData>, hosts: &HashMap<String, String>) {
    let mut clients_out = HashMap::new();
    for (ip, data) in stats {
        clients_out.insert(ip.clone(), ClientJsonStats {
            bytes_in: data.bytes_in, bytes_out: data.bytes_out, bytes_total: data.bytes_total,
            mb_in: data.bytes_in as f64 / 1_048_576.0, mb_out: data.bytes_out as f64 / 1_048_576.0, mb_total: data.bytes_total as f64 / 1_048_576.0,
            last_seen_any: if data.last_seen_any > 0. { Some(format_ts(data.last_seen_any)) } else { None },
            last_seen_out: if data.last_seen_out > 0. { Some(format_ts(data.last_seen_out)) } else { None },
            hostname: hosts.get(ip).cloned(),
        });
    }
    let root = JsonRoot { updated_at: format_ts(get_current_epoch()), clients: clients_out };
    if let Ok(json) = serde_json::to_string(&root) {
        if let Ok(mut f) = File::create(path) { let _ = f.write_all(json.as_bytes()); }
    }
}