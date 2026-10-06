use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
#[derive(Debug)]
pub struct Error {
    pub status: u16,
    pub code: String,
    pub message: String,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
fn error(status: u16, code: &str, message: &str) -> Error {
    Error {
        status,
        code: code.into(),
        message: message.into(),
    }
}
fn invalid() -> Error {
    error(0, "invalid_argument", "Invalid argument")
}
fn contract() -> &'static Value {
    static C: OnceLock<Value> = OnceLock::new();
    C.get_or_init(|| {
        serde_json::from_str(include_str!("../contract.json")).expect("generated contract")
    })
}
fn schema(name: &str) -> &'static Value {
    &contract()["schemas"][name]
}
fn valid_url(raw: &str, origin: bool) -> bool {
    if !origin && raw.chars().count() as u64 > schema("RedirectUri")["maxLength"].as_u64().unwrap()
    {
        return false;
    }
    if raw.contains(['\\', '\r', '\n', '\t', ' ']) {
        return false;
    }
    let Some((_, tail)) = raw.split_once("://") else {
        return false;
    };
    let authority = tail.split(['/', '?', '#']).next().unwrap_or("");
    let path = &tail[authority.len()..];
    if authority.contains('@') || (origin && !path.is_empty() && path != "/") {
        return false;
    }
    match Url::parse(raw) {
        Ok(u) => {
            u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
                && u.host_str().is_some()
                && (u.scheme() == "https"
                    || (u.scheme() == "http"
                        && matches!(
                            u.host_str(),
                            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
                        )))
        }
        Err(_) => false,
    }
}
fn text<'a>(p: &'a Value, key: &str) -> Result<&'a str, Error> {
    p[key].as_str().ok_or_else(invalid)
}
fn validate(s: &Value, v: &Value) -> bool {
    if let Some(r) = s["$ref"].as_str() {
        return validate(schema(r.rsplit('/').next().unwrap()), v);
    }
    let ts: Vec<&str> = if let Some(a) = s["type"].as_array() {
        a.iter().filter_map(Value::as_str).collect()
    } else {
        vec![s["type"].as_str().unwrap_or("")]
    };
    if !ts.iter().any(|t| match *t {
        "null" => v.is_null(),
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "integer" => v.is_i64() || v.is_u64() || v.as_f64().is_some_and(|n| n.fract() == 0.0),
        _ => false,
    }) {
        return false;
    }
    if v.is_null() {
        return true;
    }
    if let Some(c) = s.get("const") {
        let equal = match (c.as_f64(), v.as_f64()) {
            (Some(a), Some(b)) => a == b,
            _ => c == v,
        };
        if !equal {
            return false;
        }
    }
    if let Some(a) = s["enum"].as_array() {
        if !a.contains(v) {
            return false;
        }
    }
    if let Some(x) = v.as_str() {
        let n = x.chars().count() as u64;
        if s["minLength"].as_u64().is_some_and(|m| n < m)
            || s["maxLength"].as_u64().is_some_and(|m| n > m)
        {
            return false;
        }
        if let Some(p) = s["pattern"].as_str() {
            if !Regex::new(p).unwrap().is_match(x) {
                return false;
            }
        }
        if s["x-validation"] == "redirect" && !valid_url(x, false) {
            return false;
        }
    }
    if let Some(obj) = v.as_object() {
        if let Some(a) = s["required"].as_array() {
            if a.iter().any(|k| !obj.contains_key(k.as_str().unwrap())) {
                return false;
            }
        }
        for (k, x) in obj {
            if let Some(desc) = s["properties"].get(k) {
                if !validate(desc, x) {
                    return false;
                }
            } else if s["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(a) = v.as_array() {
        if a.iter().any(|x| !validate(&s["items"], x)) {
            return false;
        }
    }
    true
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn pkce_challenge(verifier: &str) -> Result<String, Error> {
    if !Regex::new(r"\A[A-Za-z0-9._~-]{43,128}\z")
        .unwrap()
        .is_match(verifier)
    {
        return Err(invalid());
    }
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}
pub fn create_transaction() -> Result<Value, Error> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut a)
        .map_err(|_| error(0, "crypto_error", "Random source failed"))?;
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .map_err(|_| error(0, "crypto_error", "Random source failed"))?;
    let v = URL_SAFE_NO_PAD.encode(b);
    let n = now();
    Ok(
        json!({"state":URL_SAFE_NO_PAD.encode(a),"codeVerifier":v,"codeChallenge":pkce_challenge(&v)?,"createdAt":n,"expiresAt":n+600}),
    )
}
pub fn validate_callback(p: &Value) -> Result<Value, Error> {
    let raw = text(p, "callbackUrl")?;
    let redirect = text(p, "redirectUri")?;
    let state = text(p, "state")?;
    let bytes = raw.as_bytes();
    let encoding_ok = bytes.iter().enumerate().all(|(i, b)| {
        *b != b'%'
            || (i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit())
    });
    if !valid_url(redirect, false)
        || state.is_empty()
        || p["expiresAt"]
            .as_f64()
            .is_none_or(|n| n.fract() != 0.0 || n <= now() as f64)
        || raw.contains('#')
        || raw.split('?').next() != Some(redirect)
        || !encoding_ok
    {
        return Err(invalid());
    }
    let u = Url::parse(raw).map_err(|_| invalid())?;
    let mut q = std::collections::HashMap::<String, Vec<String>>::new();
    for (k, v) in u.query_pairs() {
        q.entry(k.into_owned()).or_default().push(v.into_owned());
    }
    for k in ["state", "code", "error"] {
        if q.get(k).is_some_and(|a| a.len() > 1) {
            return Err(invalid());
        }
    }
    if q.get("state") != Some(&vec![state.to_owned()])
        || q.contains_key("code") == q.contains_key("error")
    {
        return Err(invalid());
    }
    let key = if q.contains_key("code") {
        "code"
    } else {
        "error"
    };
    let value = &q[key][0];
    if value.is_empty() {
        return Err(invalid());
    }
    Ok(json!({key:value,"state":state}))
}
pub struct Client {
    base: String,
    id: String,
    secret: String,
    http: reqwest::blocking::Client,
}
impl Client {
    pub fn new(base: &str, id: &str, secret: &str) -> Result<Self, Error> {
        let base = if base.is_empty() {
            "https://api.anyoauth.com"
        } else {
            base
        };
        if !valid_url(base, true) {
            return Err(invalid());
        }
        let http = reqwest::blocking::Client::builder()
            .user_agent("AnyOAuth-rust/0.1.0")
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| error(0, "transport_error", "Client initialization failed"))?;
        Ok(Self {
            base: base.trim_end_matches('/').into(),
            id: id.into(),
            secret: secret.into(),
            http,
        })
    }
    pub fn authorization_url(&self, p: &Value) -> Result<String, Error> {
        let provider = text(p, "provider")?;
        let redirect = text(p, "redirectUri")?;
        let state = text(p, "state")?;
        let challenge = text(p, "codeChallenge")?;
        if !validate(schema("Provider"), &json!(provider))
            || !valid_url(redirect, false)
            || state.len() < 16
            || state.len() > 512
            || !Regex::new(r"\A[A-Za-z0-9_-]{43}\z")
                .unwrap()
                .is_match(challenge)
            || self.id.is_empty()
        {
            return Err(invalid());
        }
        let mut u = Url::parse(&(self.base.clone() + "/authorize")).map_err(|_| invalid())?;
        u.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &self.id),
            ("provider", provider),
            ("redirect_uri", redirect),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ]);
        Ok(u.into())
    }
    pub fn exchange_code(&self, p: &Value) -> Result<Value, Error> {
        self.call("exchangeCode", p)
    }
    pub fn profile(&self, p: &Value) -> Result<Value, Error> {
        self.call("profile", p)
    }
    pub fn revoke(&self, p: &Value) -> Result<Value, Error> {
        self.call("revoke", p)
    }
    pub fn providers(&self, p: &Value) -> Result<Value, Error> {
        self.call("providers", p)
    }
    fn call(&self, name: &str, p: &Value) -> Result<Value, Error> {
        let op = &contract()["operations"][name];
        let method = reqwest::Method::from_bytes(op["method"].as_str().unwrap().as_bytes())
            .map_err(|_| invalid())?;
        let mut request = self
            .http
            .request(method, self.base.clone() + op["path"].as_str().unwrap())
            .header("Accept", "application/json");
        if let Some(name) = op["requestSchema"].as_str() {
            let mut body = serde_json::Map::new();
            for f in op["fields"].as_array().unwrap() {
                let wire = f["wire"].as_str().unwrap();
                let v = if let Some(v) = f.get("value") {
                    v.clone()
                } else if wire == "client_id" {
                    json!(self.id)
                } else if wire == "client_secret" {
                    json!(self.secret)
                } else {
                    p[f["param"].as_str().unwrap()].clone()
                };
                body.insert(wire.into(), v);
            }
            let body = Value::Object(body);
            if !validate(schema(name), &body) {
                return Err(invalid());
            }
            request = request.json(&body);
        }
        if op["auth"] == "bearer" {
            let token = text(p, "accessToken")?;
            if token.is_empty() || token.contains(['\r', '\n']) {
                return Err(invalid());
            }
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .map_err(|_| error(0, "transport_error", "Request failed or timed out"))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let v: Value = response.json().unwrap_or(Value::Null);
            if !validate(schema("ApiError"), &v) {
                return Err(error(status, "protocol_error", "Invalid error response"));
            }
            return Err(error(
                status,
                v["error"].as_str().unwrap(),
                v["message"].as_str().unwrap_or("HTTP request failed"),
            ));
        }
        if status as u64 != op["successStatus"].as_u64().unwrap() {
            return Err(error(
                status,
                "protocol_error",
                "Unexpected response status",
            ));
        }
        if op["responseSchema"].is_null() {
            return Ok(Value::Null);
        }
        let value: Value = response
            .json()
            .map_err(|_| error(status, "protocol_error", "Invalid response"))?;
        if !validate(schema(op["responseSchema"].as_str().unwrap()), &value) {
            return Err(error(status, "protocol_error", "Invalid response"));
        }
        Ok(value)
    }
}
