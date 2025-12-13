use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::{SystemTime, UNIX_EPOCH};
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

// Regex estático compilado uma vez só para performance
static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

#[derive(Serialize)]
pub struct ParsedLogEntry {
    pub timestamp: String,
    pub client_ip: String,
    pub client_name: String,
    pub host: String,
    pub domain: String, // igual ao host na logica atual
    pub remote_ip: String,
    pub source: String,
    pub raw: String,
}


// Retorna epoch atual em segundos (f64)
pub fn get_current_epoch() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

// Lê arquivo linha por linha para um HashSet (ex: ignores)
pub fn load_set_from_file(path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(file) = File::open(path) {
        for line in BufReader::new(file).lines() {
            if let Ok(l) = line {
                let trimmed = l.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    set.insert(trimmed.to_string());
                }
            }
        }
    }
    set
}

// Lê arquivo "IP Hostname" para um HashMap
pub fn load_map_from_file(path: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(file) = File::open(path) {
        for line in BufReader::new(file).lines() {
            if let Ok(l) = line {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 2 {
                    map.insert(parts[0].to_string(), parts[1].to_string());
                }
            }
        }
    }
    map
}

// Helper para resolver nomes com fallback
pub fn resolve_client_name(ip: &str, map: &HashMap<String, String>) -> String {
    match map.get(ip) {
        Some(name) => format!("{} ({})", ip, name),
        None => format!("{} ({})", ip, ip),
    }
}
// Regex: [+] DATE | IP (Name) -> HOST (REMOTE) | fonte=SRC
pub fn parse_log_line(line: &str) -> Option<ParsedLogEntry> {
    let re = LOG_REGEX.get_or_init(|| {
        Regex::new(r"^\[\+\]\s+([^|]+)\s+\|\s+([0-9a-fA-F\.:]+)\s+\(([^)]+)\)\s+→\s+(.+?)\s+\(([0-9a-fA-F\.:]+)\)(?:\s+\|\s+fonte=([A-Za-z0-9\-_]+))?").unwrap()
    });

    if let Some(caps) = re.captures(line) {
        let timestamp = caps[1].trim().to_string();
        let client_ip = caps[2].trim().to_string();
        let client_name = caps[3].trim().to_string();
        let host = caps[4].trim().to_string();
        let remote_ip = caps[5].trim().to_string();
        let source = caps.get(6).map_or("", |m| m.as_str()).trim().to_string();

        Some(ParsedLogEntry {
            timestamp,
            client_ip,
            client_name,
            host: host.clone(),
            domain: host,
            remote_ip,
            source,
            raw: line.to_string(),
        })
    } else {
        None
    }
}