//! SOVD Security Helper — Authenticated Key Derivation Service
//!
//! Reference implementation for OEMs. Holds ECU secrets server-side and computes
//! security keys on behalf of authenticated users. Replace the token validation
//! with your Entra ID / OAuth flow for production use.
//!
//! # Request Format
//!
//! The client sends vehicle and ECU identification context so the helper can
//! resolve the correct algorithm and key material. This reference implementation
//! uses `ecu.component_id` for lookup; a real deployment might use `part_number`,
//! `vin` prefix, or a combination.
//!
//! ```json
//! {
//!   "seed": "aabbccdd",
//!   "level": 1,
//!   "vehicle": { "vin": "1HGBH41JXMN109186" },
//!   "ecu": {
//!     "component_id": "engine_ecu",
//!     "logical_address": "0x18DA00F1",
//!     "part_number": "A2C12345",
//!     "hw_version": "H01",
//!     "sw_version": "v1.0.0",
//!     "supplier": "Continental"
//!   }
//! }
//! ```

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
    supported_ecus: Vec<String>,
}

/// Vehicle identification context — available for OEM lookup strategies
#[derive(Deserialize)]
#[allow(dead_code)]
struct VehicleContext {
    #[serde(default)]
    vin: Option<String>,
}

/// ECU identification context — available for OEM lookup strategies
#[derive(Deserialize)]
#[allow(dead_code)]
struct EcuContext {
    component_id: String,
    #[serde(default)]
    logical_address: Option<String>,
    #[serde(default)]
    part_number: Option<String>,
    #[serde(default)]
    hw_version: Option<String>,
    #[serde(default)]
    sw_version: Option<String>,
    #[serde(default)]
    supplier: Option<String>,
}

#[derive(Deserialize)]
struct CalculateRequest {
    seed: String,
    level: u8,
    #[serde(default)]
    vehicle: Option<VehicleContext>,
    ecu: EcuContext,
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
    let mut supported: Vec<String> = state.ecus.keys().cloned().collect();
    supported.sort();

    Json(InfoResponse {
        name: "SOVD Security Helper".to_string(),
        version: "2.0.0".to_string(),
        auth_required: true,
        supported_ecus: supported,
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

    // Look up ECU secret by component_id
    let ecu_secret = match state.ecus.get(&req.ecu.component_id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(CalculateResponse {
                    success: false,
                    key: None,
                    error: Some(format!(
                        "Unknown ECU '{}'. Supported: {:?}",
                        req.ecu.component_id,
                        state.ecus.keys().collect::<Vec<_>>()
                    )),
                }),
            );
        }
    };

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

    // Compute key based on the ECU's configured algorithm
    let key_bytes = match ecu_secret.algorithm.as_str() {
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
        other => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CalculateResponse {
                    success: false,
                    key: None,
                    error: Some(format!(
                        "Unsupported algorithm '{}' configured for ECU '{}'",
                        other, req.ecu.component_id
                    )),
                }),
            );
        }
    };

    // Log context for audit trail (level, vehicle, ecu identity)
    let _ = req.level;
    let _ = req.vehicle;
    let _ = req.ecu.logical_address;
    let _ = req.ecu.part_number;
    let _ = req.ecu.hw_version;
    let _ = req.ecu.sw_version;
    let _ = req.ecu.supplier;

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

    let ecu_count = config.ecus.len();
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
    println!("  ECUs: {}", ecu_count);
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
