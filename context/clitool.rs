use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_cbor as cbor;
use std::{env, fs};

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

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_request(b64req: &str) -> Result<ActivationRequest, String> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64req.trim())
        .map_err(|e| format!("base64 decode error: {e}"))?;
    cbor::from_slice::<ActivationRequest>(&raw).map_err(|e| format!("CBOR decode error: {e}"))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => {
            let sk = SigningKey::generate(&mut rand::thread_rng());
            fs::write("license_sk.bin", sk.to_bytes()).unwrap();
            let pk = sk.verifying_key();
            fs::write("license_pk.hex", hex::encode(pk.to_bytes())).unwrap();
            println!("Generated license_sk.bin and license_pk.hex");
        }
        Some("sign") => {
            // usage: sign <app_id> <hw_hash> <license_id>
            let app_id = args.get(2).expect("app_id");
            let hw_hash = args.get(3).expect("hw_hash");
            let license_id = args.get(4).expect("license_id");

            let sk_bytes = fs::read("license_sk.bin").expect("license_sk.bin");
            let sk = SigningKey::from_bytes(&sk_bytes.try_into().unwrap());

            let payload = LicensePayload {
                license_id: license_id.into(),
                app_id: app_id.into(),
                hw_hash: hw_hash.into(),
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
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Some("sign-from-request") => {
            // usage: sign-from-request <license_id> <activation_request_b64>
            let license_id = args.get(2).expect("license_id");
            let req_b64 = args.get(3).expect("activation_request_b64");

            let req = decode_request(req_b64).expect("bad activation request");
            let sk_bytes = fs::read("license_sk.bin").expect("license_sk.bin");
            let sk = SigningKey::from_bytes(&sk_bytes.try_into().unwrap());

            let payload = LicensePayload {
                license_id: license_id.into(),
                app_id: req.app_id,   // use the app_id from the request
                hw_hash: req.hw_hash, // <-- the important part
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
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        _ => eprintln!(
            "Usage:
  license-signer gen
  license-signer sign <app_id> <hw_hash> <license_id>
  license-signer sign-from-request <license_id> <activation_request_b64>"
        ),
    }
}
