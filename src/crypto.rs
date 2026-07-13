use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub const KEY_SIZE: usize = 32;
pub const PUBKEY_SIZE: usize = 32;

pub struct Handshake {
    secret: Option<EphemeralSecret>,
    pub public: PublicKey,
}

impl Handshake {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    pub fn derive_key(&mut self, peer_public: &PublicKey) -> Result<[u8; KEY_SIZE]> {
        let secret = self.secret.take().context("derive_key called twice")?;
        let shared = secret.diffie_hellman(peer_public);
        let hk = Hkdf::<Sha256>::new(Some(b"bobvpn-v1"), shared.as_bytes());
        let mut key = [0u8; KEY_SIZE];
        hk.expand(b"tunnel-key", &mut key).map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(key)
    }
}

pub fn encrypt(key: &[u8; KEY_SIZE], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = make_nonce(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))
}

pub fn decrypt(
    key: &[u8; KEY_SIZE],
    counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = make_nonce(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))
}

fn make_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

pub fn preshared_hash(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b"bobvpn-auth-v1");
    hasher.finalize().into()
}

pub fn load_preshared_secret() -> Result<[u8; 32]> {
    let path = crate::config::secret_path();
    let secret_bytes: [u8; 32] = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading secret from {}", path.display()))?;
        let content = content.trim();
        let bytes = hex::decode(content)
            .with_context(|| format!("invalid hex in {}", path.display()))?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("secret must be 32 bytes"))?
    } else {
        let mut secret = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut secret);
        let parent = path.parent().context("invalid secret path")?;
        std::fs::create_dir_all(parent)?;
        std::fs::write(&path, hex::encode(secret))?;
        log::info!("generated new preshared secret at {}", path.display());
        secret
    };
    log::info!("preshared secret: {}", hex::encode(secret_bytes));
    Ok(preshared_hash(&secret_bytes))
}

pub fn build_auth_payload(handshake: &Handshake, psk_hash: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PUBKEY_SIZE + 32);
    payload.extend_from_slice(handshake.public.as_bytes());
    let mut combined = Vec::with_capacity(PUBKEY_SIZE + 32);
    combined.extend_from_slice(psk_hash);
    combined.extend_from_slice(handshake.public.as_bytes());
    let hash: [u8; 32] = Sha256::digest(&combined).into();
    payload.extend_from_slice(&hash);
    payload
}

pub fn verify_auth_payload(
    payload: &[u8],
    psk_hash: &[u8; 32],
) -> Result<PublicKey> {
    anyhow::ensure!(payload.len() >= PUBKEY_SIZE + 32, "auth payload too short");
    let peer_pub_bytes: [u8; PUBKEY_SIZE] = payload[..PUBKEY_SIZE].try_into()?;
    let peer_hash: [u8; 32] = payload[PUBKEY_SIZE..PUBKEY_SIZE + 32].try_into()?;

    let mut combined = Vec::with_capacity(PUBKEY_SIZE + 32);
    combined.extend_from_slice(psk_hash);
    combined.extend_from_slice(&peer_pub_bytes);
    let expected: [u8; 32] = Sha256::digest(&combined).into();

    anyhow::ensure!(peer_hash == expected, "authentication failed: bad preshared secret");

    Ok(PublicKey::from(peer_pub_bytes))
}
