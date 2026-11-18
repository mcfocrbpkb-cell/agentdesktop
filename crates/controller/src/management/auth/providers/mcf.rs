use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::RwLock;
use tracing::warn;

use super::super::{
    Error, Provider, RequestMode,
    authentication::{Principal, PrincipalKind},
    authorization::{AccessRequest, Verb, permission_names},
};

const SESSION_COOKIE: &str = "mcf_access";
const RECENT_AUTH: i64 = 15 * 60;

#[derive(Clone)]
pub struct McfAccess {
    client: Client,
    login_url: String,
    logout_url: String,
    jwks_url: String,
    issuer: String,
    audience: String,
    public_url: String,
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub base_url: String,
    pub jwks_url: String,
    pub issuer: String,
    pub audience: String,
    pub request_timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Clone, Debug, Deserialize)]
struct LoginResponse {
    access_token: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    iat: Option<i64>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    mcf: Map<String, Value>,
}

impl McfAccess {
    pub async fn new(config: Config, public_url: String) -> anyhow::Result<Self> {
        let timeout = Duration::from_secs(config.request_timeout_seconds.unwrap_or(8));
        anyhow::ensure!(timeout >= Duration::from_secs(1) && timeout <= Duration::from_secs(30), "MCF request timeout must be 1..30 seconds");
        anyhow::ensure!(config.base_url.starts_with("https://"), "MCF AI-KU base_url must use HTTPS");
        anyhow::ensure!(config.jwks_url.starts_with("https://"), "MCF AI-KU jwks_url must use HTTPS");
        let client = Client::builder().timeout(timeout).build()?;
        let provider = Self {
            client,
            login_url: format!("{}/v1/auth/ad/login", config.base_url.trim_end_matches('/')),
            logout_url: format!("{}/v1/auth/logout", config.base_url.trim_end_matches('/')),
            jwks_url: config.jwks_url,
            issuer: config.issuer,
            audience: config.audience,
            public_url,
            keys: Arc::new(RwLock::new(HashMap::new())),
        };
        provider.refresh_keys().await?;
        Ok(provider)
    }

    async fn refresh_keys(&self) -> Result<(), Error> {
        let response = self.client.get(&self.jwks_url).send().await.map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "mcf_identity_unavailable"))?;
        if !response.status().is_success() {
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "mcf_identity_unavailable"));
        }
        let jwks: Jwks = response.json().await.map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "mcf_jwks_invalid"))?;
        let mut keys = HashMap::new();
        for key in jwks.keys {
            let decoding = DecodingKey::from_rsa_components(&key.n, &key.e).map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "mcf_jwks_invalid"))?;
            keys.insert(key.kid, decoding);
        }
        if keys.is_empty() {
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "mcf_jwks_empty"));
        }
        *self.keys.write().await = keys;
        Ok(())
    }

    async fn verify(&self, token: &str) -> Result<Principal, Error> {
        let header = decode_header(token).map_err(|_| Error(StatusCode::UNAUTHORIZED, "invalid_mcf_token"))?;
        if header.alg != Algorithm::RS256 {
            return Err(Error(StatusCode::UNAUTHORIZED, "invalid_mcf_algorithm"));
        }
        let key = {
            let keys = self.keys.read().await;
            keys.get(header.kid.as_deref().unwrap_or("")).cloned()
        };
        let key = match key {
            Some(key) => key,
            None => {
                self.refresh_keys().await?;
                let keys = self.keys.read().await;
                keys.get(header.kid.as_deref().unwrap_or("")).cloned().ok_or(Error(StatusCode::UNAUTHORIZED, "unknown_mcf_key"))?
            }
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let token = decode::<Claims>(token, &key, &validation).map_err(|_| Error(StatusCode::UNAUTHORIZED, "invalid_mcf_token"))?;
        let claims = token.claims;
        let mut map = Map::new();
        map.insert("roles".into(), serde_json::to_value(&claims.roles).unwrap_or(Value::Array(vec![])));
        map.insert("mcf".into(), Value::Object(claims.mcf));
        map.insert("iat".into(), Value::from(claims.iat.unwrap_or_default()));
        let auth_time = claims.iat;
        Ok(Principal {
            issuer: claims.iss,
            subject: claims.sub,
            kind: PrincipalKind::Human,
            claims: map,
            auth_time,
            claims_verified_at: now(),
        })
    }

    fn cookie(headers: &HeaderMap) -> Option<String> {
        headers.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|pair| {
            let mut parts = pair.trim().splitn(2, '=');
            if parts.next()? == SESSION_COOKIE { Some(parts.next()?.to_owned()) } else { None }
        })
    }

    fn roles(principal: &Principal) -> Vec<String> {
        principal.claims.get("roles").and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect())
            .unwrap_or_default()
    }

    fn cookie_response(token: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600")).expect("validated cookie header")
    }

    fn clear_cookie() -> HeaderValue {
        HeaderValue::from_static("mcf_access=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
    }
}

#[async_trait]
impl Provider for McfAccess {
    fn routes(&self) -> Router {
        Router::new()
            .route("/auth/session", get(session))
            .route("/auth/login", get(login_page).post(login))
            .route("/auth/logout", post(logout))
            .route("/auth/activity", post(activity))
            .with_state(self.clone())
    }

    async fn authenticate(&self, headers: &HeaderMap, _mode: RequestMode) -> Result<Option<Principal>, Error> {
        let Some(token) = Self::cookie(headers) else { return Ok(None) };
        match self.verify(&token).await {
            Ok(principal) => Ok(Some(principal)),
            Err(_) => Ok(None),
        }
    }

    async fn check(&self, principal: &Principal, _headers: &HeaderMap, access: AccessRequest<'_>) -> Result<(), Error> {
        let roles = Self::roles(principal);
        let elevated = roles.iter().any(|role| role == "SUPERADMIN" || role == "ADMIN");
        if elevated { return Ok(()) }
        if matches!(access.verb, Verb::Read | Verb::List)
            && roles.iter().any(|role| matches!(role.as_str(), "PROJECT_ADMIN" | "DEPARTMENT_ADMIN" | "TEAM_ADMIN"))
        {
            return Ok(());
        }
        if access.verb.is_mutation() {
            let auth_time = principal.auth_time.unwrap_or(0);
            if now() - auth_time > RECENT_AUTH {
                return Err(Error(StatusCode::FORBIDDEN, "reauthentication_required"));
            }
        }
        Err(Error(StatusCode::FORBIDDEN, "permission_denied"))
    }
}

async fn login_page() -> Html<&'static str> {
    Html(r#"<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCF AI-KU Login</title><style>body{font-family:system-ui;background:#f5f8ff;display:grid;place-items:center;min-height:100vh}.card{background:#fff;padding:32px;border-radius:20px;box-shadow:0 20px 70px #0001;width:min(400px,90vw)}form{display:grid;gap:12px}input,button{padding:12px;border-radius:10px;border:1px solid #dbe3f0}button{background:#1e66f5;color:white;font-weight:700}</style></head><body><div class="card"><h1>MCF AI-KU</h1><p>Masuk menggunakan Active Directory.</p><form method="post"><input name="username" autocomplete="username" placeholder="AD username" required><input name="password" type="password" autocomplete="current-password" placeholder="AD password" required><button>Masuk</button></form></div></body></html>"#)
}

async fn login(State(provider): State<McfAccess>, Form(form): Form<LoginForm>) -> Response {
    if form.username.trim().is_empty() || form.password.is_empty() {
        return Error(StatusCode::BAD_REQUEST, "credentials_required").into_response();
    }
    let response = match provider.client.post(&provider.login_url).json(&json!({"username":form.username,"password":form.password})).send().await {
        Ok(response) => response,
        Err(_) => return Error(StatusCode::SERVICE_UNAVAILABLE, "mcf_identity_unavailable").into_response(),
    };
    if !response.status().is_success() {
        return Error(StatusCode::UNAUTHORIZED, "invalid_directory_credentials").into_response();
    }
    let payload = match response.json::<LoginResponse>().await {
        Ok(payload) => payload,
        Err(_) => return Error(StatusCode::SERVICE_UNAVAILABLE, "invalid_mcf_login_response").into_response(),
    };
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(header::SET_COOKIE, McfAccess::cookie_response(&payload.access_token));
    response
}

async fn logout(headers: HeaderMap, State(provider): State<McfAccess>) -> Response {
    let mut revocation_ok = true;
    if let Some(token) = McfAccess::cookie(&headers) {
        // Revoke the server-side MCF session before clearing the browser cookie.
        // A stolen session token must not remain usable after an explicit logout.
        revocation_ok = match provider
            .client
            .post(&provider.logout_url)
            .bearer_auth(&token)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => true,
            Ok(response) => {
                warn!(status = response.status().as_u16(), "MCF session revocation returned a non-success status");
                false
            }
            Err(error) => {
                warn!(%error, "MCF session revocation request failed");
                false
            }
        };
    }
    let mut response = if revocation_ok {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Error(StatusCode::SERVICE_UNAVAILABLE, "mcf_session_revocation_unavailable").into_response()
    };
    response.headers_mut().insert(header::SET_COOKIE, McfAccess::clear_cookie());
    response
}

async fn activity() -> StatusCode { StatusCode::NO_CONTENT }

async fn session(headers: HeaderMap, State(provider): State<McfAccess>) -> Response {
    let Some(token) = McfAccess::cookie(&headers) else {
        return Json(json!({"mode":"authenticated","authenticated":false,"subject":null,"role":null,"assurance":null,"recent_auth_required":false,"permissions":permission_names()})).into_response();
    };
    match provider.verify(&token).await {
        Ok(principal) => {
            let roles=McfAccess::roles(&principal);
            let role=roles.iter().find(|r| *r=="SUPERADMIN"||*r=="ADMIN"||*r=="PROJECT_ADMIN"||*r=="DEPARTMENT_ADMIN"||*r=="TEAM_ADMIN").cloned();
            Json(json!({"mode":"authenticated","authenticated":true,"subject":principal.subject,"role":role,"assurance":"ad","recent_auth_required":principal.auth_time.map(|t| now()-t>RECENT_AUTH).unwrap_or(true),"permissions":permission_names()})).into_response()
        }
        Err(_) => Json(json!({"mode":"authenticated","authenticated":false,"subject":null,"role":null,"assurance":null,"recent_auth_required":false,"permissions":permission_names()})).into_response()
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}
