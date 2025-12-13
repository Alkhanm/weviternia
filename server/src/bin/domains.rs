use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use chrono::{TimeZone, Local};
use regex::Regex;
// Importa nossa lib compartilhada
use traffic_utils::{get_current_epoch, load_map_from_file, load_set_from_file, resolve_client_name};

const GROUP_WINDOW: f64 = 5.0;
const RELOAD_INTERVAL: f64 = 10.0;

struct Config {
    iface: String,
    lan_regex: Regex,
    gateway_ip: String,
    log_file: String,
    ignore_domains_path: String,
    ignore_clients_path: String,
    hosts_map_path: String,
}

struct DnsPending {
    timestamp: f64,
    remote_ip: String,
}

fn main() {
    let config = load_config();
    
    if let Some(parent) = std::path::Path::new(&config.log_file).parent() {
        let _ = fs::create_dir_all(parent);
    }
    println!("[domains] Monitorando domínios na interface: {}", config.iface);

    let mut ignore_domains: HashSet<String> = HashSet::new();
    let mut ignore_clients: HashSet<String> = HashSet::new();
    let mut hosts_map: HashMap<String, String> = HashMap::new();
    let mut last_reload = 0.0;
    
    let mut dns_cache: HashMap<(String, String), DnsPending> = HashMap::new();
    let mut last_log_map: HashMap<String, f64> = HashMap::new();

    let mut child = Command::new("tshark")
        .args(&[
            "-i", &config.iface, "-n", "-l", "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
            "-e", "dns.qry.name", "-e", "tls.handshake.extensions_server_name", "-e", "http.host",
            "-Y", "dns.qry.name or tls.handshake.extensions_server_name or http.host"
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Falha ao iniciar tshark");

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    for line_result in reader.lines() {
        let line = match line_result { Ok(l) => l, Err(_) => break };
        let now = get_current_epoch();

        if now - last_reload >= RELOAD_INTERVAL {
            ignore_domains = load_set_from_file(&config.ignore_domains_path);
            ignore_clients = load_set_from_file(&config.ignore_clients_path);
            hosts_map = load_map_from_file(&config.hosts_map_path);
            last_reload = now;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 3 { continue; }

        let ts_pkt: f64 = fields[0].parse().unwrap_or(now);
        let src = fields[1];
        let dst = fields[2];
        let dns_name = fields.get(3).unwrap_or(&"");
        let tls_sni = fields.get(4).unwrap_or(&"");
        let http_host = fields.get(5).unwrap_or(&"");

        let (domain, fonte) = if !dns_name.is_empty() { (*dns_name, "DNS") }
                              else if !tls_sni.is_empty() { (*tls_sni, "TLS") }
                              else if !http_host.is_empty() { (*http_host, "HTTP") }
                              else { continue; };

        if ignore_domains.contains(domain) { continue; }

        let (client, remote) = if config.lan_regex.is_match(src) && !config.lan_regex.is_match(dst) { (src, dst) }
        else if config.lan_regex.is_match(dst) && !config.lan_regex.is_match(src) { (dst, src) }
        else if config.lan_regex.is_match(src) && config.lan_regex.is_match(dst) { (src, dst) }
        else { continue; };

        if ignore_clients.contains(client) { continue; }

        // Limpeza Cache DNS
        let expired: Vec<_> = dns_cache.iter()
            .filter(|(_, v)| ts_pkt - v.timestamp > GROUP_WINDOW)
            .map(|(k, _)| k.clone()).collect();
        for k in expired {
            if let Some(v) = dns_cache.remove(&k) {
                write_log(&config.log_file, v.timestamp, &k.0, &k.1, &v.remote_ip, "DNS", &hosts_map, true);
            }
        }

        // Deduplicação
        let cache_key = (client.to_string(), domain.to_string());
        if fonte == "DNS" && remote == config.gateway_ip {
            dns_cache.insert(cache_key, DnsPending { timestamp: ts_pkt, remote_ip: remote.to_string() });
            continue;
        } else if fonte == "TLS" || fonte == "HTTP" {
            dns_cache.remove(&cache_key);
        }

        let log_key = format!("{}|{}|{}|{}", client, domain, remote, fonte);
        if let Some(&last_ts) = last_log_map.get(&log_key) {
            if ts_pkt - last_ts <= 1.0 { continue; }
        }
        last_log_map.insert(log_key, ts_pkt);

        write_log(&config.log_file, ts_pkt, client, domain, remote, fonte, &hosts_map, false);
    }
}

fn load_config() -> Config {
    Config {
        iface: env::var("IFACE").unwrap_or_else(|_| "enx00e04c68054d".to_string()),
        lan_regex: Regex::new(&env::var("LAN_REGEX").unwrap_or_else(|_| "^192\\.168\\.1\\.".to_string())).unwrap(),
        gateway_ip: env::var("GATEWAY_IP").unwrap_or_else(|_| "192.168.1.1".to_string()),
        log_file: env::var("LOG_FILE").unwrap_or_else(|_| "/var/log/traffic-domains/traffic-domains.log".to_string()),
        ignore_domains_path: env::var("IGNORE_FILE").unwrap_or_else(|_| "/etc/traffic-monitor/ignore-domains.txt".to_string()),
        ignore_clients_path: env::var("IGNORE_CLIENTS_FILE").unwrap_or_else(|_| "/etc/traffic-monitor/ignore-clients.txt".to_string()),
        hosts_map_path: env::var("HOSTS_MAP_FILE").unwrap_or_else(|_| "/etc/traffic-monitor/lan-hosts.txt".to_string()),
    }
}

fn write_log(logfile: &str, ts: f64, client: &str, domain: &str, remote: &str, fonte: &str, map: &HashMap<String, String>, delayed: bool) {
    let client_display = resolve_client_name(client, map);
    let dt = Local.timestamp_opt(ts as i64, 0).unwrap();
    let ts_str = dt.format("%Y-%m-%d %H:%M:%S").to_string();
    let line = if delayed {
        format!("[+] {} | {} → {} (via DNS: {}) | fonte={}\n", ts_str, client_display, domain, remote, fonte)
    } else {
        format!("[+] {} | {} → {} ({}) | fonte={}\n", ts_str, client_display, domain, remote, fonte)
    };
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(logfile) {
        let _ = f.write_all(line.as_bytes());
    }
}