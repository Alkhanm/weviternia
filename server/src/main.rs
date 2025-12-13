use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{Local, TimeZone};
use regex::Regex;

// --- Configurações e Constantes ---
const GROUP_WINDOW: f64 = 5.0; // Janela de tempo para agrupar DNS + HTTPS
const RELOAD_INTERVAL: f64 = 10.0; // Recarregar arquivos a cada 10s

struct Config {
    iface: String,
    lan_regex: Regex,
    gateway_ip: String,
    log_file: String,
    ignore_domains_path: String,
    ignore_clients_path: String,
    hosts_map_path: String,
}

// Estrutura para o Cache DNS pendente
struct DnsPending {
    timestamp: f64,
    remote_ip: String,
}

fn main() {
    // 1. Carrega configurações (Variáveis de ambiente ou Defaults)
    let config = load_config();
    
    // Cria diretório de log se não existir
    if let Some(parent) = std::path::Path::new(&config.log_file).parent() {
        let _ = fs::create_dir_all(parent);
    }

    println!("[rust-analyzer] Interface: {}", config.iface);
    println!("[rust-analyzer] Log: {}", config.log_file);

    // 2. Estados Mutáveis (Caches e Listas)
    let mut ignore_domains: HashSet<String> = HashSet::new();
    let mut ignore_clients: HashSet<String> = HashSet::new();
    let mut hosts_map: HashMap<String, String> = HashMap::new();
    
    // Timers para recarga
    let mut last_reload = 0.0;

    // Cache de lógica
    // Key: (ClientIP, Domain) -> Value: DnsPending
    let mut dns_cache: HashMap<(String, String), DnsPending> = HashMap::new();
    
    // Deduplicação de log: Key: "Client|Domain|Remote|Fonte" -> Timestamp
    let mut last_log_map: HashMap<String, f64> = HashMap::new();

    // 3. Inicia o Tshark
    let mut child = Command::new("tshark")
        .args(&[
            "-i", &config.iface,
            "-n", "-l",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "dns.qry.name",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "http.host",
            "-Y", "dns.qry.name or tls.handshake.extensions_server_name or http.host"
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // Silencia stderr do tshark
        .spawn()
        .expect("Falha ao iniciar o tshark. Verifique se está instalado.");

    let stdout = child.stdout.take().expect("Falha ao capturar stdout");
    let reader = BufReader::new(stdout);

    // 4. Loop de Processamento
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break, 
        };

        // Timestamp atual para lógica de controle
        let now = get_current_epoch();

        // --- Recarga de Arquivos ---
        if now - last_reload >= RELOAD_INTERVAL {
            ignore_domains = load_set_from_file(&config.ignore_domains_path);
            ignore_clients = load_set_from_file(&config.ignore_clients_path);
            hosts_map = load_map_from_file(&config.hosts_map_path);
            last_reload = now;
        }

        // Parse da linha do Tshark (separada por TAB)
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 3 { continue; }

        // Extração de campos
        let ts_pkt_str = fields[0];
        let src = fields[1];
        let dst = fields[2];
        
        // Colunas opcionais (podem estar vazias)
        let dns_name = fields.get(3).unwrap_or(&"");
        let tls_sni = fields.get(4).unwrap_or(&"");
        let http_host = fields.get(5).unwrap_or(&"");

        let ts_pkt: f64 = ts_pkt_str.parse().unwrap_or(now);

        // Identifica Domínio e Fonte
        let (domain, fonte) = if !dns_name.is_empty() { (*dns_name, "DNS") }
                              else if !tls_sni.is_empty() { (*tls_sni, "TLS") }
                              else if !http_host.is_empty() { (*http_host, "HTTP") }
                              else { continue; };

        // Filtro de Domínios Ignorados (Regex Check simples)
        // Nota: Se a lista de ignore for regex complexo, precisaríamos iterar regexes.
        // Aqui assumi string match exato ou regex simples carregado como string.
        // Para manter compatível com seu script que usa regex, iteramos:
        if is_ignored_domain(domain, &ignore_domains) { continue; }

        // Identifica Cliente vs Remoto
        let (client, remote) = if config.lan_regex.is_match(src) && !config.lan_regex.is_match(dst) {
            (src, dst)
        } else if config.lan_regex.is_match(dst) && !config.lan_regex.is_match(src) {
            (dst, src)
        } else if config.lan_regex.is_match(src) && config.lan_regex.is_match(dst) {
            (src, dst) // Tráfego interno
        } else {
            continue; 
        };

        // Filtro de Clientes Ignorados
        if is_ignored_client(client, &ignore_clients) { continue; }

        // --- Limpeza do Cache DNS Antigo ---
        // (Verifica itens expirados e loga)
        let expired_keys: Vec<(String, String)> = dns_cache.iter()
            .filter(|(_, entry)| ts_pkt - entry.timestamp > GROUP_WINDOW)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            if let Some(entry) = dns_cache.remove(&key) {
                let (c_ip, d_dom) = key;
                write_log(&config.log_file, entry.timestamp, &c_ip, &d_dom, &entry.remote_ip, "DNS", &hosts_map, true);
            }
        }

        // --- Lógica de Deduplicação Inteligente ---
        let cache_key = (client.to_string(), domain.to_string());

        if fonte == "DNS" && remote == config.gateway_ip {
            // Guarda no cache e espera conexão real
            dns_cache.insert(cache_key, DnsPending { timestamp: ts_pkt, remote_ip: remote.to_string() });
            continue; 
        } else if fonte == "TLS" || fonte == "HTTP" {
            // Se houver DNS pendente para este destino, removemos (foi "confirmado")
            dns_cache.remove(&cache_key);
        }

        // --- Deduplicação de Log (Flood Control) ---
        // Chave única para o log
        let log_key = format!("{}|{}|{}|{}", client, domain, remote, fonte);
        if let Some(&last_ts) = last_log_map.get(&log_key) {
            if ts_pkt - last_ts <= 1.0 {
                continue; // Ignora se repetiu em menos de 1s
            }
        }
        last_log_map.insert(log_key, ts_pkt);

        // --- Escreve Log ---
        write_log(&config.log_file, ts_pkt, client, domain, remote, fonte, &hosts_map, false);
    }
}

// --- Funções Auxiliares ---

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

fn get_current_epoch() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

// Lê arquivo linha por linha e coloca num HashSet (ignorando comentários)
fn load_set_from_file(path: &str) -> HashSet<String> {
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

// Lê arquivo "IP Hostname" e coloca num HashMap
fn load_map_from_file(path: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(file) = File::open(path) {
        for line in BufReader::new(file).lines() {
            if let Ok(l) = line {
                let trimmed = l.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
                
                // Split por espaço ou tab
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    map.insert(parts[0].to_string(), parts[1].to_string());
                }
            }
        }
    }
    map
}

// Checa se o domínio bate com algum regex da lista (Aqui simulamos regex com contains/match simples para performance, 
// mas se precisar de REGEX real no arquivo de ignore, precisaria compilar todos eles).
fn is_ignored_domain(domain: &str, ignore_list: &HashSet<String>) -> bool {
    for pattern in ignore_list {
        // Simulação básica de regex do awk: se pattern está contido no domain ou é regex
        // Para uma implementação Rust robusta de "arquivo de regexes", precisariamos compilar Regex::new() para cada linha.
        // Aqui, assumiremos que se a linha contém texto, verificamos se o domínio contém esse texto.
        // Se quiser regex real, altere HashSet<String> para Vec<Regex>.
        if let Ok(re) = Regex::new(pattern) {
             if re.is_match(domain) { return true; }
        }
    }
    false
}

fn is_ignored_client(client: &str, ignore_list: &HashSet<String>) -> bool {
    for pattern in ignore_list {
        if let Ok(re) = Regex::new(pattern) {
             if re.is_match(client) { return true; }
        }
    }
    false
}

fn resolve_client_name(ip: &str, map: &HashMap<String, String>) -> String {
    match map.get(ip) {
        Some(name) => format!("{} ({})", ip, name), // IP (Hostname)
        None => format!("{} ({})", ip, ip),         // IP (IP)
    }
}

fn write_log(logfile: &str, ts: f64, client: &str, domain: &str, remote: &str, fonte: &str, hosts_map: &HashMap<String, String>, is_dns_delayed: bool) {
    let client_display = resolve_client_name(client, hosts_map);
    
    // Converte timestamp para string legível local
    let dt = Local.timestamp_opt(ts as i64, 0).unwrap();
    let ts_str = dt.format("%Y-%m-%d %H:%M:%S").to_string();

    let log_line = if is_dns_delayed {
        format!("[+] {} | {} → {} (via DNS: {}) | fonte={}\n", ts_str, client_display, domain, remote, fonte)
    } else {
        format!("[+] {} | {} → {} ({}) | fonte={}\n", ts_str, client_display, domain, remote, fonte)
    };

    // Abre arquivo em modo append
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(logfile) {
        let _ = file.write_all(log_line.as_bytes());
    }
}