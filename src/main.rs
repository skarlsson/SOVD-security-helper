//! SOVD Security Helper — Authenticated Key Derivation Service
//!
//! Reference implementation for OEMs. Holds ECU secrets server-side and computes
//! security keys on behalf of authenticated users. Replace the token validation
//! with your Entra ID / OAuth flow for production use.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

// =============================================================================
// CLI / Configuration
// =============================================================================

#[derive(Parser)]
#[command(name = "sovd-security-helper", about = "Security key derivation helper for SOVD Explorer")]
struct Cli {
    /// Port to listen on
    #[arg(long, default_value = "9100")]
    port: u16,

    /// Bearer token for authentication (can also set SOVD_HELPER_TOKEN env var)
    #[arg(long, env = "SOVD_HELPER_TOKEN")]
    token: String,

    /// Path to secrets TOML config file
    #[arg(long, default_value = "config/secrets.toml")]
    config: String,
}

#[derive(Deserialize)]
struct SecretsConfig {
    ecus: HashMap<String, EcuSecret>,
}

#[derive(Deserialize, Clone)]
struct EcuSecret {
    algorithm: String,
    secret: String,
}

// =============================================================================
// API Types
// =============================================================================

#[derive(Serialize)]
struct InfoResponse {
    name: String,
    version: String,
    auth_required: bool,
    algorithms: Vec<AlgorithmInfo>,
}

#[derive(Serialize)]
struct AlgorithmInfo {
    id: String,
    name: String,
    ecu_types: Vec<String>,
}

#[derive(Deserialize)]
struct CalculateRequest {
    seed: String,
    level: u8,
    ecu_type: String,
    algorithm: String,
}

#[derive(Serialize)]
struct CalculateResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// =============================================================================
// Shared State
// =============================================================================

struct AppState {
    token: String,
    ecus: HashMap<String, EcuSecret>,
}

// =============================================================================
// Handlers
// =============================================================================

async fn info_handler(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    // Group ECU types by algorithm
    let mut algo_ecus: HashMap<String, Vec<String>> = HashMap::new();
    for (ecu_type, secret) in &state.ecus {
        algo_ecus
            .entry(secret.algorithm.clone())
            .or_default()
            .push(ecu_type.clone());
    }

    let algorithms = algo_ecus
        .into_iter()
        .map(|(id, mut ecu_types)| {
            ecu_types.sort();
            let name = match id.as_str() {
                "xor" => "XOR with shared secret".to_string(),
                other => other.to_string(),
            };
            AlgorithmInfo {
                id,
                name,
                ecu_types,
            }
        })
        .collect();

    Json(InfoResponse {
        name: "SOVD Test ECU Security Helper".to_string(),
        version: "1.0.0".to_string(),
        auth_required: true,
        algorithms,
    })
}

async fn calculate_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CalculateRequest>,
) -> (StatusCode, Json<CalculateResponse>) {
    // Validate Bearer token
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let provided_token = auth.strip_prefix("Bearer ").unwrap_or("");
    if provided_token != state.token {
        return (
            StatusCode::UNAUTHORIZED,
            Json(CalculateResponse {
                success: false,
                key: None,
                error: Some("Invalid or missing token".to_string()),
            }),
        );
    }

    // Look up ECU secret
    let ecu_secret = match state.ecus.get(&req.ecu_type) {
        Some(s) => s,
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(CalculateResponse {
                    success: false,
                    key: None,
                    error: Some(format!("User not authorized for ECU type '{}'", req.ecu_type)),
                }),
            );
        }
    };

    // Verify algorithm matches
    if ecu_secret.algorithm != req.algorithm {
        return (
            StatusCode::BAD_REQUEST,
            Json(CalculateResponse {
                success: false,
                key: None,
                error: Some(format!(
                    "Algorithm mismatch: ECU '{}' uses '{}', not '{}'",
                    req.ecu_type, ecu_secret.algorithm, req.algorithm
                )),
            }),
        );
    }

    // Parse seed hex
    let seed_bytes = match hex::decode(&req.seed) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(CalculateResponse {
                    success: false,
                    key: None,
                    error: Some(format!("Invalid seed hex: {}", e)),
                }),
            );
        }
    };

    // Parse secret hex
    let secret_bytes = match hex::decode(&ecu_secret.secret) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CalculateResponse {
                    success: false,
                    key: None,
                    error: Some(format!("Server config error: invalid secret hex: {}", e)),
                }),
            );
        }
    };

    // Compute key based on algorithm
    let key_bytes = match req.algorithm.as_str() {
        "xor" => {
            if secret_bytes.is_empty() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(CalculateResponse {
                        success: false,
                        key: None,
                        error: Some("Server config error: empty secret".to_string()),
                    }),
                );
            }
            seed_bytes
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ secret_bytes[i % secret_bytes.len()])
                .collect::<Vec<u8>>()
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(CalculateResponse {
                    success: false,
                    key: None,
                    error: Some(format!("Unsupported algorithm: {}", req.algorithm)),
                }),
            );
        }
    };

    let _ = req.level; // Reserved for future per-level key derivation

    (
        StatusCode::OK,
        Json(CalculateResponse {
            success: true,
            key: Some(hex::encode(key_bytes)),
            error: None,
        }),
    )
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load secrets config
    let config_str = std::fs::read_to_string(&cli.config).unwrap_or_else(|e| {
        eprintln!("Failed to read config '{}': {}", cli.config, e);
        std::process::exit(1);
    });

    let config: SecretsConfig = toml::from_str(&config_str).unwrap_or_else(|e| {
        eprintln!("Failed to parse config '{}': {}", cli.config, e);
        std::process::exit(1);
    });

    let state = Arc::new(AppState {
        token: cli.token.clone(),
        ecus: config.ecus,
    });

    let app = Router::new()
        .route("/info", get(info_handler))
        .route("/calculate", post(calculate_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    println!("SOVD Security Helper listening on http://{}", addr);
    println!("  ECU types: {:?}", config_str.matches("[ecus.").count());
    println!("  Token: {}...", &cli.token[..cli.token.len().min(4)]);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        });

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    });
}
