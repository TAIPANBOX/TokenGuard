//! Real APNs sender (feature `apns`). Token-based auth: a provider JWT signed
//! ES256 with the `.p8` key (a P-256 private key), sent over HTTP/2. Configured
//! entirely from the environment; absent config means push stays disabled
//! (see `main::build_push_sender`). Not exercised in CI beyond compilation — a
//! live run needs an Apple Developer key + a real device.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::json;

use crate::push::{ActivityUpdate, Push, PushSender};

pub struct ApnsSender {
    inner: Arc<ApnsInner>,
}

struct ApnsInner {
    client: reqwest::Client,
    signing_key: SigningKey,
    key_id: String,
    team_id: String,
    topic: String,
    host: String,
    /// Cached provider JWT + its issued-at, regenerated well within APNs' limit.
    jwt: Mutex<Option<(String, i64)>>,
}

impl ApnsSender {
    /// Build from `TOKENFUSE_APNS_{KEY_PATH,KEY_ID,TEAM_ID,TOPIC,ENV}`; `None` if
    /// any required var is missing or the key can't be read.
    pub fn from_env() -> Option<Self> {
        let key_path = std::env::var("TOKENFUSE_APNS_KEY_PATH").ok()?;
        let key_id = std::env::var("TOKENFUSE_APNS_KEY_ID").ok()?;
        let team_id = std::env::var("TOKENFUSE_APNS_TEAM_ID").ok()?;
        let topic = std::env::var("TOKENFUSE_APNS_TOPIC").ok()?;
        let production = std::env::var("TOKENFUSE_APNS_ENV").ok().as_deref() == Some("production");
        let host = if production {
            "https://api.push.apple.com"
        } else {
            "https://api.sandbox.push.apple.com"
        }
        .to_string();

        let pem = std::fs::read_to_string(&key_path).ok()?;
        let secret = p256::SecretKey::from_pkcs8_pem(&pem).ok()?;
        let signing_key = SigningKey::from(secret);
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .ok()?;

        Some(Self {
            inner: Arc::new(ApnsInner {
                client,
                signing_key,
                key_id,
                team_id,
                topic,
                host,
                jwt: Mutex::new(None),
            }),
        })
    }
}

impl ApnsInner {
    /// The provider token, minting a fresh one if the cached one is old.
    fn provider_jwt(&self) -> String {
        let now = now_unix();
        if let Some((jwt, iat)) = self.jwt.lock().unwrap().as_ref() {
            if now - iat < 2400 {
                return jwt.clone();
            }
        }
        let header = URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":self.key_id}).to_string());
        let claims = URL_SAFE_NO_PAD.encode(json!({"iss":self.team_id,"iat":now}).to_string());
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        *self.jwt.lock().unwrap() = Some((jwt.clone(), now));
        jwt
    }

    async fn post(
        &self,
        target: &str,
        push_type: &str,
        topic_suffix: &str,
        payload: serde_json::Value,
    ) {
        let jwt = self.provider_jwt();
        let url = format!("{}/3/device/{target}", self.host);
        let _ = self
            .client
            .post(&url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", format!("{}{topic_suffix}", self.topic))
            .header("apns-push-type", push_type)
            .json(&payload)
            .send()
            .await;
    }
}

impl PushSender for ApnsSender {
    fn send(&self, push: Push) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let payload = json!({
                "aps": { "alert": { "title": push.title, "body": push.body }, "sound": "default" },
                "run_id": push.run_id,
                "reason": push.reason,
                // Incident deep-link fields — null for kill/budget alerts.
                "incident_id": push.incident_id,
                "kind": push.kind,
            });
            inner
                .post(&push.device_apns_token, "alert", "", payload)
                .await;
        });
    }

    fn update_activity(&self, update: ActivityUpdate) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let event = if update.ended { "end" } else { "update" };
            let payload = json!({
                "aps": {
                    "timestamp": now_unix(),
                    "event": event,
                    "content-state": {
                        "spent_microusd": update.spent_microusd,
                        "budget_micros": update.budget_micros,
                    },
                },
            });
            inner
                .post(
                    &update.activity_token,
                    "liveactivity",
                    ".push-type.liveactivity",
                    payload,
                )
                .await;
        });
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
