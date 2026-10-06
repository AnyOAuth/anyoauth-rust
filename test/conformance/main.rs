use anyoauth_sdk::*;
use serde_json::{json, Value};
use std::io::{self, Read};
fn run() -> Result<Value, Error> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|_| Error {
        status: 0,
        code: "invalid_argument".into(),
        message: "Invalid input".into(),
    })?;
    let v: Value = serde_json::from_str(&input).map_err(|_| Error {
        status: 0,
        code: "invalid_argument".into(),
        message: "Invalid input".into(),
    })?;
    let p = &v["params"];
    let c = Client::new(
        v["baseUrl"].as_str().unwrap_or(""),
        v["clientId"].as_str().unwrap_or(""),
        v["clientSecret"].as_str().unwrap_or(""),
    )?;
    match v["action"].as_str().unwrap_or("") {
        "exchangeCode" => c.exchange_code(p),
        "profile" => c.profile(p),
        "revoke" => c.revoke(p),
        "providers" => c.providers(p),
        "pkceChallenge" => {
            pkce_challenge(p["codeVerifier"].as_str().unwrap_or("")).map(|s| json!(s))
        }
        "createTransaction" => create_transaction(),
        "authorizationUrl" => c.authorization_url(p).map(|s| json!(s)),
        "validateCallback" => validate_callback(p),
        _ => Err(Error {
            status: 0,
            code: "invalid_argument".into(),
            message: "Unknown action".into(),
        }),
    }
}
fn main() {
    let output = match run() {
        Ok(result) => json!({"ok":true,"result":result}),
        Err(e) => json!({"ok":false,"error":{"status":e.status,"code":e.code,"message":e.message}}),
    };
    println!("{}", output);
}
