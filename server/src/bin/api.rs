use axum::{
    extract::{Query, Json},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tower_http::services::ServeDir;
use tower_http::cors::CorsLayer;
use traffic_utils::{parse_log_line, ParsedLogEntry}; // Importa da nossa lib
use chrono::{Local, Duration};

// --- Configurações ---
const HOST: [u8; 4] = [100, 76, 63, 123];
const PORT: u16 = 9080;

// Caminhos Padrão (podem vir de ENV)
fn get_env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

struct Config {
    web_dir: String,
    log_file: String,
    bytes_file: String,
    ignore_file: String,
}

impl Config {
    fn load() -> Self {
        // Assume rodando em /opt/traffic-monitor/bin, web em ../web
        let base_dir = std::env::var("BASE_DIR").unwrap_or_else(|_| "/opt/traffic-monitor".to_string());
        Self {
            web_dir: format!("{}/web", base_dir),
            log_file: get_env("LOG_FILE", "/var/log/traffic-domains/traffic-domains.log"),
            bytes_file: get_env("BYTES_FILE", "/var/log/traffic-domains/traffic-bytes.json"),
            ignore_file: get_env("IGNORE_FILE", "/etc/traffic-monitor/ignore-domains.txt"),
        }
    }
}

#[tokio::main]
async fn main() {
    let config = Config::load();
    println!("Iniciando Web API em {}:{}. Servindo estáticos de: {}", 
             std::net::Ipv4Addr::from(HOST), PORT, config.web_dir);

    // Configura Rotas
    let app = Router::new()
        // API Routes
        .route("/logs", get(handle_logs))
        .route("/log-days", get(handle_log_days))
        .route("/bytes", get(handle_bytes))
        .route("/clients", get(handle_clients))
        .route("/ignored-domains", get(handle_get_ignored)
            .post(handle_post_ignored)
            .delete(handle_delete_ignored))
        // CORREÇÃO AQUI:
        // Use nest_service na raiz ("/").
        // O Axum prioriza rotas específicas (como /logs) antes de cair no nest_service.
        // O nest_service já converte os erros de IO do ServeDir automaticamente.
        .nest_service("/", ServeDir::new(&config.web_dir))
        .layer(CorsLayer::permissive()) // Habilita CORS para dev
        .with_state(std::sync::Arc::new(config));

    let addr = SocketAddr::from((HOST, PORT));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct LogsQuery {
    client: Option<String>,
    limit: Option<usize>,
    date: Option<String>,
}

#[derive(Serialize)]
struct LogsResponse {
    entries: Vec<ParsedLogEntry>,
    date: Option<String>,
}

async fn handle_logs(
    Query(params): Query<LogsQuery>,
    axum::extract::State(config): axum::extract::State<std::sync::Arc<Config>>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(1000).clamp(1, 5000);
    let client_filter = params.client.as_deref().unwrap_or("").trim();
    let date_str = params.date.as_deref().unwrap_or("").trim();

    // Resolve arquivo de log
    let file_path = resolve_log_path(&config.log_file, date_str);
    
    if !file_path.exists() {
        return Json(LogsResponse { entries: vec![], date: Some(date_str.to_string()) });
    }

    // Lê arquivo (inverte ordem manualmente para pegar os mais recentes)
    // Nota: Ler arquivo inteiro na RAM pode ser custoso se o log for gigante.
    // Em produção real, usaríamos `rev_lines` crate ou seek do fim.
    let content = match fs::read_to_string(&file_path) {
        Ok(c) => c,
        Err(_) => return Json(LogsResponse { entries: vec![], date: Some(date_str.to_string()) }),
    };

    let mut entries = Vec::new();
    // Itera reverso
    for line in content.lines().rev() {
        if line.trim().is_empty() { continue; }
        
        if let Some(entry) = parse_log_line(line) {
            if !client_filter.is_empty() && client_filter != "all" && entry.client_ip != client_filter {
                continue;
            }
            entries.push(entry);
            if entries.len() >= limit { break; }
        }
    }

    Json(LogsResponse { entries, date: Some(date_str.to_string()) })
}

fn resolve_log_path(base_log: &str, date_str: &str) -> PathBuf {
    let today = Local::now().format("%Y-%m-%d").to_string();
    if date_str.is_empty() || date_str == today {
        return PathBuf::from(base_log);
    }
    // Formato log rotated: traffic-domains.log-2025-12-01
    PathBuf::from(format!("{}-{}", base_log, date_str))
}

// --- Handler: Log Days ---

#[derive(Serialize)]
struct LogDaysResponse { days: Vec<String> }

async fn handle_log_days(
    axum::extract::State(config): axum::extract::State<std::sync::Arc<Config>>,
) -> impl IntoResponse {
    let mut days = Vec::new();
    let today = Local::now().date_naive();

    // Checa últimos 30 dias
    for i in 0..30 {
        let date = today - Duration::days(i);
        let date_str = date.format("%Y-%m-%d").to_string();
        let path = resolve_log_path(&config.log_file, &date_str);
        
        if path.exists() {
            days.push(date_str);
        }
    }
    Json(LogDaysResponse { days })
}

// --- Handlers: Bytes/Clients ---

async fn handle_bytes(
    axum::extract::State(config): axum::extract::State<std::sync::Arc<Config>>,
) -> impl IntoResponse {
    match fs::read_to_string(&config.bytes_file) {
        Ok(content) => Response::builder()
            .header("content-type", "application/json")
            .body(axum::body::Body::from(content))
            .unwrap(),
        Err(_) => Json(serde_json::json!({"updated_at": null, "clients": {}})).into_response(),
    }
}

async fn handle_clients(
    axum::extract::State(config): axum::extract::State<std::sync::Arc<Config>>,
) -> impl IntoResponse {
    // Lê o JSON de bytes e extrai keys
    let content = fs::read_to_string(&config.bytes_file).unwrap_or_else(|_| "{}".to_string());
    let json: serde_json::Value = serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
    
    let mut clients = Vec::new();
    if let Some(obj) = json.get("clients").and_then(|c| c.as_object()) {
        clients = obj.keys().cloned().collect();
        clients.sort();
    }

    Json(serde_json::json!({ "clients": clients }))
}

// --- Handlers: Ignored Domains ---

#[derive(Serialize)]
struct IgnoredDomainsResponse { domains: Vec<String> }

#[derive(Deserialize)]
struct DomainPayload { domain: String }

fn read_ignored_list(path: &str) -> Vec<String> {
    if let Ok(file) = File::open(path) {
        BufReader::new(file)
            .lines()
            .filter_map(|l| l.ok())
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        vec![]
    }
}

fn write_ignored_list(path: &str, domains: Vec<String>) {
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let unique: HashSet<_> = domains.into_iter().collect();
    let content = unique.into_iter().collect::<Vec<_>>().join("\n");
    let _ = fs::write(path, format!("# Domínios ignorados\n{}\n", content));
}

async fn handle_get_ignored(
    axum::extract::State(config): axum::extract::State<std::sync::Arc<Config>>,
) -> impl IntoResponse {
    Json(IgnoredDomainsResponse { domains: read_ignored_list(&config.ignore_file) })
}

async fn handle_post_ignored(
    axum::extract::State(config): axum::extract::State<std::sync::Arc<Config>>,
    Json(payload): Json<DomainPayload>,
) -> impl IntoResponse {
    let domain = payload.domain.trim().to_string();
    if domain.is_empty() { return (StatusCode::BAD_REQUEST, "Invalid domain").into_response(); }

    let mut domains = read_ignored_list(&config.ignore_file);
    if !domains.contains(&domain) {
        domains.push(domain);
        write_ignored_list(&config.ignore_file, domains.clone());
    }
    Json(IgnoredDomainsResponse { domains }).into_response()
}

async fn handle_delete_ignored(
    axum::extract::State(config): axum::extract::State<std::sync::Arc<Config>>,
    Query(params): Query<DomainPayload>, // Aceita via query param ?domain=...
) -> impl IntoResponse {
    let domain = params.domain.trim();
    let mut domains = read_ignored_list(&config.ignore_file);
    
    if let Some(pos) = domains.iter().position(|x| x == domain) {
        domains.remove(pos);
        write_ignored_list(&config.ignore_file, domains.clone());
    }
    Json(IgnoredDomainsResponse { domains }).into_response()
}