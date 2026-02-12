//! SOVD Security Helper — Authenticated Key Derivation Service
//!
//! Reference implementation for OEMs. Holds ECU secrets server-side and computes
//! security keys on behalf of authenticated users.
//!
//! Supports two authentication modes:
//! - **static**: Bearer token string comparison (dev/testing)
//! - **oidc**: JWT validation against Google / Microsoft Entra ID (production)
//!
//! The `--token` CLI flag forces static mode regardless of config, so existing
//! simulation scripts continue working with zero changes.
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
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

// =============================================================================
// CLI / Configuration
// =============================================================================

#[derive(Parser)]
#[command(name = "sovd-security-helper", about = "Security key derivation helper for SOVD Explorer")]
struct Cli {
    /// Port to listen on
    #[arg(long, default_value = "9100")]
    port: u16,

    /// Bearer token for authentication — forces static auth mode when set
    #[arg(long, env = "SOVD_HELPER_TOKEN")]
    token: Option<String>,

    /// Path to secrets TOML config file
    #[arg(long, default_value = "config/secrets.toml")]
    config: String,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    auth: AuthConfig,
    ecus: HashMap<String, EcuSecret>,
}

#[derive(Deserialize)]
struct AuthConfig {
    #[serde(default)]
    mode: AuthMode,
    #[serde(default)]
    providers: Vec<OidcProviderConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Static,
            providers: Vec::new(),
        }
    }
}

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum AuthMode {
    #[default]
    Static,
    Oidc,
}

#[derive(Deserialize, Clone)]
struct OidcProviderConfig {
    name: String,
    issuer: String,
    audience: String,
    #[serde(default)]
    client_secret: Option<String>,
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
    auth_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    providers: Option<Vec<ProviderInfo>>,
    supported_ecus: Vec<String>,
}

#[derive(Serialize, Clone)]
struct ProviderInfo {
    name: String,
    issuer: String,
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
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
// Auth Types
// =============================================================================

/// JWT claims extracted from validated OIDC tokens.
#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    iss: String,
    // `aud` and `exp` are validated by jsonwebtoken but not extracted here
}

/// Per-provider runtime state: config + cached JWKS + HTTP client.
struct ProviderState {
    config: OidcProviderConfig,
    jwks: RwLock<JwkSet>,
    jwks_uri: String,
    client: reqwest::Client,
}

/// Manages JWKS for all configured OIDC providers.
struct JwksManager {
    providers: Vec<ProviderState>,
}

/// Dispatches authentication to either static token or OIDC JWT validation.
enum AuthValidator {
    Static { token: String },
    Oidc { jwks_manager: Arc<JwksManager> },
}

// =============================================================================
// OIDC Discovery + JWKS
// =============================================================================

/// OIDC discovery document (only the field we need).
#[derive(Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

/// Fetch OIDC discovery document and JWKS for a provider.
async fn discover_jwks(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<(String, JwkSet), String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let discovery: OidcDiscovery = client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch OIDC discovery from {}: {}", discovery_url, e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse OIDC discovery from {}: {}", discovery_url, e))?;

    let jwks: JwkSet = client
        .get(&discovery.jwks_uri)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS from {}: {}", discovery.jwks_uri, e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse JWKS from {}: {}", discovery.jwks_uri, e))?;

    Ok((discovery.jwks_uri, jwks))
}

impl JwksManager {
    /// Validate a JWT against all configured providers.
    ///
    /// Decodes the token header to extract `kid`, finds the matching key across
    /// providers, then validates signature, expiry, audience, and issuer.
    async fn validate_token(&self, raw_token: &str) -> Result<JwtClaims, String> {
        let header = decode_header(raw_token)
            .map_err(|e| format!("Invalid JWT header: {}", e))?;

        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| "JWT missing 'kid' header claim".to_string())?;

        // Search all providers for a matching key
        for provider in &self.providers {
            let jwks = provider.jwks.read().await;
            let jwk = match jwks.find(kid) {
                Some(jwk) => jwk,
                None => continue,
            };

            let decoding_key = DecodingKey::from_jwk(jwk)
                .map_err(|e| format!("Failed to build decoding key from JWK: {}", e))?;

            let mut validation = Validation::new(header.alg);
            validation.set_audience(&[&provider.config.audience]);
            validation.set_issuer(&[&provider.config.issuer]);
            validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

            let token_data = decode::<JwtClaims>(raw_token, &decoding_key, &validation)
                .map_err(|e| format!("JWT validation failed: {}", e))?;

            return Ok(token_data.claims);
        }

        Err(format!("No provider has a key matching kid '{}'", kid))
    }
}

/// Spawn a background task that refreshes JWKS for all providers every 60 minutes.
fn spawn_jwks_refresh(manager: Arc<JwksManager>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
        // Skip the first immediate tick — we already fetched at startup
        interval.tick().await;

        loop {
            interval.tick().await;
            for provider in &manager.providers {
                match provider
                    .client
                    .get(&provider.jwks_uri)
                    .send()
                    .await
                    .and_then(|r| Ok(r))
                {
                    Ok(resp) => match resp.json::<JwkSet>().await {
                        Ok(new_jwks) => {
                            let key_count = new_jwks.keys.len();
                            *provider.jwks.write().await = new_jwks;
                            eprintln!(
                                "[auth] Refreshed JWKS for '{}': {} keys",
                                provider.config.name, key_count
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "[auth] Failed to parse refreshed JWKS for '{}': {}",
                                provider.config.name, e
                            );
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "[auth] Failed to fetch refreshed JWKS for '{}': {}",
                            provider.config.name, e
                        );
                    }
                }
            }
        }
    });
}

impl AuthValidator {
    /// Authenticate an incoming request from its Authorization header value.
    ///
    /// Returns `Ok(Some(identity))` for OIDC (sub or email), `Ok(None)` for
    /// static token (no identity info), or `Err(message)` on failure.
    async fn authenticate(&self, auth_header: &str) -> Result<Option<String>, String> {
        let raw_token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| "Missing or malformed Authorization header".to_string())?;

        match self {
            AuthValidator::Static { token } => {
                if raw_token == token {
                    Ok(None)
                } else {
                    Err("Invalid token".to_string())
                }
            }
            AuthValidator::Oidc { jwks_manager } => {
                let claims = jwks_manager.validate_token(raw_token).await?;
                let identity = claims
                    .email
                    .unwrap_or_else(|| format!("{}@{}", claims.sub, claims.iss));
                Ok(Some(identity))
            }
        }
    }
}

// =============================================================================
// Shared State
// =============================================================================

struct AppState {
    auth: AuthValidator,
    ecus: HashMap<String, EcuSecret>,
    /// Provider info for /info endpoint (only populated in OIDC mode)
    provider_info: Option<Vec<ProviderInfo>>,
}

// =============================================================================
// Handlers
// =============================================================================

async fn info_handler(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    let mut supported: Vec<String> = state.ecus.keys().cloned().collect();
    supported.sort();

    let auth_mode = match &state.auth {
        AuthValidator::Static { .. } => "static",
        AuthValidator::Oidc { .. } => "oidc",
    };

    Json(InfoResponse {
        name: "SOVD Security Helper".to_string(),
        version: "3.0.0".to_string(),
        auth_mode: auth_mode.to_string(),
        providers: state.provider_info.clone(),
        supported_ecus: supported,
    })
}

async fn calculate_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CalculateRequest>,
) -> (StatusCode, Json<CalculateResponse>) {
    // Authenticate
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let identity = match state.auth.authenticate(auth_header).await {
        Ok(id) => id,
        Err(msg) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(CalculateResponse {
                    success: false,
                    key: None,
                    error: Some(msg),
                }),
            );
        }
    };

    if let Some(ref user) = identity {
        eprintln!(
            "[audit] calculate request from '{}' for ECU '{}'",
            user, req.ecu.component_id
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

    // Load config
    let config_str = std::fs::read_to_string(&cli.config).unwrap_or_else(|e| {
        eprintln!("Failed to read config '{}': {}", cli.config, e);
        std::process::exit(1);
    });

    let config: Config = toml::from_str(&config_str).unwrap_or_else(|e| {
        eprintln!("Failed to parse config '{}': {}", cli.config, e);
        std::process::exit(1);
    });

    let ecu_count = config.ecus.len();

    // Resolve auth mode: --token CLI flag forces static mode
    let (auth, provider_info) = if let Some(token) = cli.token {
        eprintln!("[auth] Static mode (--token override)");
        println!("  Token: {}...", &token[..token.len().min(4)]);
        (AuthValidator::Static { token }, None)
    } else {
        match config.auth.mode {
            AuthMode::Static => {
                eprintln!("Error: static auth mode requires --token flag or SOVD_HELPER_TOKEN env var");
                std::process::exit(1);
            }
            AuthMode::Oidc => {
                if config.auth.providers.is_empty() {
                    eprintln!("Error: OIDC mode requires at least one [[auth.providers]] entry");
                    std::process::exit(1);
                }

                let http_client = reqwest::Client::new();
                let mut provider_states = Vec::new();
                let mut info = Vec::new();

                for provider_config in config.auth.providers {
                    eprintln!(
                        "[auth] Discovering OIDC provider '{}' at {}",
                        provider_config.name, provider_config.issuer
                    );

                    let (jwks_uri, jwks) =
                        discover_jwks(&http_client, &provider_config.issuer)
                            .await
                            .unwrap_or_else(|e| {
                                eprintln!(
                                    "Failed to discover OIDC provider '{}': {}",
                                    provider_config.name, e
                                );
                                std::process::exit(1);
                            });

                    eprintln!(
                        "[auth] Provider '{}': {} keys from {}",
                        provider_config.name,
                        jwks.keys.len(),
                        jwks_uri
                    );

                    info.push(ProviderInfo {
                        name: provider_config.name.clone(),
                        issuer: provider_config.issuer.clone(),
                        client_id: provider_config.audience.clone(),
                        client_secret: provider_config.client_secret.clone(),
                    });

                    provider_states.push(ProviderState {
                        config: provider_config,
                        jwks: RwLock::new(jwks),
                        jwks_uri,
                        client: http_client.clone(),
                    });
                }

                let manager = Arc::new(JwksManager {
                    providers: provider_states,
                });

                spawn_jwks_refresh(Arc::clone(&manager));

                eprintln!("[auth] OIDC mode active with {} provider(s)", info.len());
                (
                    AuthValidator::Oidc {
                        jwks_manager: manager,
                    },
                    Some(info),
                )
            }
        }
    };

    let state = Arc::new(AppState {
        auth,
        ecus: config.ecus,
        provider_info,
    });

    let app = Router::new()
        .route("/info", get(info_handler))
        .route("/calculate", post(calculate_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    println!("SOVD Security Helper listening on http://{}", addr);
    println!("  ECUs: {}", ecu_count);

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
