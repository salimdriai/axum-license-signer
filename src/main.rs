use axum::{
    response::Html,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_cbor as cbor;
use std::fs;

const INDEX_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Signer</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        section { border: 1px solid #ccc; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
        h2 { margin-top: 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, textarea { width: 100%; padding: 8px; margin-bottom: 15px; box-sizing: border-box; }
        button { padding: 10px 20px; background-color: #007bff; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background-color: #0056b3; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>License Signer Tool</h1>

    <section>
        <h2>1. Generate Keys</h2>
        <p>Generate a new Keypair (private `license_sk.bin` and public `license_pk.hex`) in the server's working directory.</p>
        <button onclick="generateKeys()">Generate Keys</button>
        <pre id="keyOutput"></pre>
    </section>

    <section>
        <h2>2. Generate License</h2>
        <form id="licenseForm" onsubmit="signLicense(event)">
            <label for="licenseId">License ID:</label>
            <input type="text" id="licenseId" name="license_id" required>

            <label for="activationRequest">Activation Request (Base64):</label>
            <textarea id="activationRequest" name="activation_request" rows="4" required placeholder="Paste the base64 activation request here..."></textarea>

            <button type="submit">Sign License</button>
        </form>
        <pre id="licenseOutput"></pre>
    </section>

    <script>
        async function generateKeys() {
            const output = document.getElementById('keyOutput');
            output.textContent = "Generating...";
            try {
                const res = await fetch('/keys/gen', { method: 'POST' });
                const text = await res.text();
                output.textContent = text;
            } catch (e) {
                output.textContent = "Error: " + e;
            }
        }

        async function signLicense(e) {
            e.preventDefault();
            const output = document.getElementById('licenseOutput');
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData.entries());
            
            output.textContent = "Signing...";
            try {
                const res = await fetch('/license/sign', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const json = await res.json();
                output.textContent = JSON.stringify(json, null, 2);
            } catch (e) {
                output.textContent = "Error: " + e;
            }
        }
    </script>
</body>
</html>
"#;

#[derive(Serialize, Deserialize)]
struct LicensePayload {
    license_id: String,
    app_id: String,
    hw_hash: String,
    issued_at: chrono::DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    features: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct SignedLicense {
    payload_b64: String,
    sig_b64: String,
}

#[derive(Deserialize)]
struct ActivationRequest {
    app_id: String,
    // version: String,
    hw_hash: String,
    // created_at: chrono::DateTime<Utc>,
    // nonce_b64: String,
}

#[derive(Deserialize)]
struct SignRequest {
    license_id: String,
    activation_request: String,
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_request(b64req: &str) -> Result<ActivationRequest, String> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64req.trim())
        .map_err(|e| format!("base64 decode error: {e}"))?;
    cbor::from_slice::<ActivationRequest>(&raw).map_err(|e| format!("CBOR decode error: {e}"))
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn generate_keys() -> String {
    let sk = SigningKey::generate(&mut rand::thread_rng());
    if let Err(e) = fs::write("license_sk.bin", sk.to_bytes()) {
        return format!("Failed to write license_sk.bin: {}", e);
    }

    let pk = sk.verifying_key();
    let pk_hex = hex::encode(pk.to_bytes());
    if let Err(e) = fs::write("license_pk.hex", &pk_hex) {
        return format!("Failed to write license_pk.hex: {}", e);
    }

    format!(
        "Generated license_sk.bin and license_pk.hex in server directory.\nPublic Key (Hex): {}",
        pk_hex
    )
}

async fn sign_license(Json(req): Json<SignRequest>) -> Result<Json<SignedLicense>, String> {
    let act_req =
        decode_request(&req.activation_request).map_err(|e| format!("Bad request: {}", e))?;

    let sk_bytes = fs::read("license_sk.bin")
        .map_err(|_| "license_sk.bin not found. Please generate keys first.".to_string())?;
    let sk = SigningKey::from_bytes(&sk_bytes.try_into().unwrap());

    let payload = LicensePayload {
        license_id: req.license_id,
        app_id: act_req.app_id,
        hw_hash: act_req.hw_hash,
        issued_at: Utc::now(),
        expires_at: None,
        features: None,
    };

    let bytes = cbor::to_vec(&payload).unwrap();
    let sig = sk.sign(&bytes);
    let out = SignedLicense {
        payload_b64: b64(&bytes),
        sig_b64: b64(&sig.to_bytes()),
    };

    Ok(Json(out))
}

#[shuttle_runtime::main]
async fn main() -> shuttle_axum::ShuttleAxum {
    let router = Router::new()
        .route("/", get(index))
        .route("/keys/gen", post(generate_keys))
        .route("/license/sign", post(sign_license));

    Ok(router.into())
}
