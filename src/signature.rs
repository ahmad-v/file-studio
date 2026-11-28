//! Versioned detached Ed25519 signatures over a streamed SHA-256 file digest.
//!
//! The signature envelope is JSON, while the Ed25519 key and signature bytes
//! use their standard raw encodings as lowercase hexadecimal. The signed
//! message is domain-separated and contains the file byte length and SHA-256
//! digest. A signature proves possession of a key; the fingerprint still needs
//! to be compared with a separately trusted value.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use localwright_core::{read_bounded, write_bytes, write_new, Error, Job, Result};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const MESSAGE_DOMAIN: &[u8] = b"File Studio detached signature v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKeyFile {
    schema_version: u8,
    algorithm: String,
    private_seed_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyFile {
    schema_version: u8,
    algorithm: String,
    public_key_hex: String,
    fingerprint_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureFile {
    schema_version: u8,
    algorithm: String,
    message_format: String,
    file_bytes: u64,
    sha256: String,
    public_key_hex: String,
    fingerprint_sha256: String,
    signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyOptions {
    signature_path: String,
    #[serde(default)]
    trusted_public_key_path: Option<String>,
}

pub fn generate_key(output: &Path) -> Result<Value> {
    ensure_private_output_parent(output)?;
    let signing = SigningKey::generate(&mut OsRng);
    let mut seed = signing.to_bytes();
    let public = signing.verifying_key().to_bytes();
    let fingerprint = fingerprint(&public);
    let key_file = PrivateKeyFile {
        schema_version: 1,
        algorithm: "Ed25519".into(),
        private_seed_hex: hex::encode(seed),
    };
    seed.fill(0);
    let encoded = serde_json::to_vec_pretty(&key_file)?;
    write_bytes(output, &encoded)?;
    Ok(json!({
        "schema_version": 1,
        "algorithm": "Ed25519",
        "private_key_file": output,
        "public_key_hex": hex::encode(public),
        "fingerprint_sha256": fingerprint,
        "private_key_encrypted": false,
    }))
}

pub fn export_public(private_path: &Path, output: &Path) -> Result<Value> {
    let signing = load_private(private_path)?;
    let public = signing.verifying_key().to_bytes();
    let key = PublicKeyFile {
        schema_version: 1,
        algorithm: "Ed25519".into(),
        public_key_hex: hex::encode(public),
        fingerprint_sha256: fingerprint(&public),
    };
    write_bytes(output, &serde_json::to_vec_pretty(&key)?)?;
    Ok(json!({
        "schema_version": 1,
        "algorithm": "Ed25519",
        "public_key_file": output,
        "fingerprint_sha256": key.fingerprint_sha256,
    }))
}

pub fn sign(input: &Path, output: &Path, key_path: &Path, job: &Job) -> Result<Value> {
    let signing = load_private(key_path)?;
    let public = signing.verifying_key().to_bytes();
    let (digest, bytes) = digest_file(input, job)?;
    let message = signed_message(bytes, &digest);
    let signature = signing.sign(&message);
    let envelope = SignatureFile {
        schema_version: 1,
        algorithm: "Ed25519".into(),
        message_format: "file-studio-sha256-v1".into(),
        file_bytes: bytes,
        sha256: hex::encode(digest),
        public_key_hex: hex::encode(public),
        fingerprint_sha256: fingerprint(&public),
        signature_hex: hex::encode(signature.to_bytes()),
    };
    job.check()?;
    write_new(output, |file| {
        serde_json::to_writer_pretty(file, &envelope)?;
        Ok(())
    })?;
    Ok(json!({
        "schema_version": 1,
        "algorithm": "Ed25519",
        "signed_file_bytes": bytes,
        "sha256": envelope.sha256,
        "signature_file": output,
        "signer_fingerprint_sha256": envelope.fingerprint_sha256,
    }))
}

pub fn verify(input: &Path, options_json: &str, job: &Job) -> Result<Value> {
    if options_json.len() > 16 * 1024 {
        return Err(Error::input(
            "Signature verification settings exceed 16 KiB",
        ));
    }
    let options: VerifyOptions = serde_json::from_str(options_json).map_err(|_| {
        Error::input(
            "Parameter must be JSON with signature_path and optional trusted_public_key_path",
        )
    })?;
    if options.signature_path.is_empty() {
        return Err(Error::input("Choose a detached signature file"));
    }
    let signature_bytes = read_bounded(Path::new(&options.signature_path), MAX_SIGNATURE_BYTES)?;
    let envelope: SignatureFile = serde_json::from_slice(&signature_bytes)
        .map_err(|_| Error::input("Detached signature is not a valid File Studio signature"))?;
    if envelope.schema_version != 1
        || envelope.algorithm != "Ed25519"
        || envelope.message_format != "file-studio-sha256-v1"
    {
        return Err(Error::input(
            "Unsupported detached signature version or algorithm",
        ));
    }
    let public_bytes = decode_exact::<32>(&envelope.public_key_hex, "public key")?;
    let public = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| Error::input("Signature contains an invalid Ed25519 public key"))?;
    let actual_fingerprint = fingerprint(&public_bytes);
    if envelope.fingerprint_sha256 != actual_fingerprint {
        return Err(Error::input(
            "Signature public-key fingerprint does not match",
        ));
    }

    if let Some(path) = options.trusted_public_key_path.as_deref() {
        let trusted: PublicKeyFile =
            serde_json::from_slice(&read_bounded(Path::new(path), MAX_KEY_BYTES)?)
                .map_err(|_| Error::input("Trusted public-key file is invalid"))?;
        if trusted.schema_version != 1 || trusted.algorithm != "Ed25519" {
            return Err(Error::input("Unsupported trusted public-key format"));
        }
        let trusted_bytes = decode_exact::<32>(&trusted.public_key_hex, "trusted public key")?;
        if trusted.fingerprint_sha256 != fingerprint(&trusted_bytes)
            || trusted_bytes != public_bytes
        {
            return Err(Error::input(
                "Signature key does not match the selected trusted public key",
            ));
        }
    }

    let signature_bytes = decode_exact::<64>(&envelope.signature_hex, "signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let (digest, bytes) = digest_file(input, job)?;
    if bytes != envelope.file_bytes || hex::encode(digest) != envelope.sha256 {
        return Err(Error::input(
            "Signed file size or SHA-256 digest does not match",
        ));
    }
    public
        .verify(&signed_message(bytes, &digest), &signature)
        .map_err(|_| Error::input("Detached signature verification failed"))?;
    Ok(json!({
        "schema_version": 1,
        "algorithm": "Ed25519",
        "verified": true,
        "file_bytes": bytes,
        "sha256": envelope.sha256,
        "signer_fingerprint_sha256": actual_fingerprint,
        "trusted_key_matched": options.trusted_public_key_path.is_some(),
    }))
}

fn digest_file(path: &Path, job: &Job) -> Result<([u8; 32], u64)> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > MAX_FILE_BYTES {
        return Err(Error::input(
            "Choose a regular, non-symlink file up to 4 GiB",
        ));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.len() != before.len()
        || opened.modified()? != before.modified()?
    {
        return Err(Error::input("File changed while it was being opened"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        job.check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| Error::input("File size overflow"))?;
        if total > before.len() || total > MAX_FILE_BYTES {
            return Err(Error::input("File grew while being processed"));
        }
        hasher.update(&buffer[..count]);
        job.progress(total, before.len());
    }
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if total != before.len()
        || after.len() != before.len()
        || after.modified()? != before.modified()?
        || path_after.len() != before.len()
        || path_after.modified()? != before.modified()?
    {
        return Err(Error::input("File changed during signature processing"));
    }
    Ok((hasher.finalize().into(), total))
}

fn signed_message(bytes: u64, digest: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(MESSAGE_DOMAIN.len() + 8 + digest.len());
    message.extend_from_slice(MESSAGE_DOMAIN);
    message.extend_from_slice(&bytes.to_be_bytes());
    message.extend_from_slice(digest);
    message
}

fn fingerprint(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))
}

fn decode_exact<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes =
        hex::decode(value).map_err(|_| Error::input(format!("Invalid {label} encoding")))?;
    bytes
        .try_into()
        .map_err(|_| Error::input(format!("Invalid {label} length")))
}

fn load_private(path: &Path) -> Result<SigningKey> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::input(
            "Private key must be a regular, non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::input(
                "Private key permissions are too broad; restrict access to its owner",
            ));
        }
    }
    let key: PrivateKeyFile = serde_json::from_slice(&read_bounded(path, MAX_KEY_BYTES)?)
        .map_err(|_| Error::input("Private-key file is invalid"))?;
    if key.schema_version != 1 || key.algorithm != "Ed25519" {
        return Err(Error::input("Unsupported private-key format"));
    }
    let seed = decode_exact::<32>(&key.private_seed_hex, "private key")?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(windows)]
fn ensure_private_output_parent(path: &Path) -> Result<()> {
    let profile = std::env::var_os("USERPROFILE").ok_or_else(|| {
        Error::input("Cannot locate the Windows user profile for private key output")
    })?;
    let profile = fs::canonicalize(profile)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    if !parent.starts_with(profile) {
        return Err(Error::input(
            "Save private key files inside your Windows user profile",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn ensure_private_output_parent(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detached_ed25519_sign_and_verify_and_reject_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("private.json");
        let public_path = directory.path().join("public.json");
        let signature_path = directory.path().join("file.sig.json");
        let input = directory.path().join("payload.bin");
        fs::write(&input, b"signed content\0\xff").unwrap();
        generate_key(&key_path).unwrap();
        export_public(&key_path, &public_path).unwrap();
        sign(&input, &signature_path, &key_path, &Job::new()).unwrap();
        let options = serde_json::json!({"signature_path":signature_path,"trusted_public_key_path":public_path}).to_string();
        let verified = verify(&input, &options, &Job::new()).unwrap();
        assert_eq!(verified["verified"], true);
        assert_eq!(verified["trusted_key_matched"], true);
        fs::write(&input, b"tampered").unwrap();
        assert!(verify(&input, &options, &Job::new()).is_err());
    }

    #[test]
    fn signature_refuses_overwrite_and_wrong_trusted_key() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("private.json");
        let other_key_path = directory.path().join("other.json");
        let public_path = directory.path().join("public.json");
        let input = directory.path().join("payload.txt");
        let signature_path = directory.path().join("payload.sig.json");
        fs::write(&input, b"data").unwrap();
        generate_key(&key_path).unwrap();
        generate_key(&other_key_path).unwrap();
        export_public(&key_path, &public_path).unwrap();
        sign(&input, &signature_path, &key_path, &Job::new()).unwrap();
        let original = fs::read(&signature_path).unwrap();
        assert!(sign(&input, &signature_path, &key_path, &Job::new()).is_err());
        assert_eq!(fs::read(&signature_path).unwrap(), original);
        export_public(&other_key_path, &directory.path().join("wrong.pub")).unwrap();
        let wrong = serde_json::json!({"signature_path":signature_path,"trusted_public_key_path":directory.path().join("wrong.pub")}).to_string();
        assert!(verify(&input, &wrong, &Job::new()).is_err());
    }
}
