#![forbid(unsafe_code)]

use age::{
    secrecy::{ExposeSecret, SecretString},
    x25519, Decryptor, Encryptor,
};
use localwright_core::{write_bytes, write_new, Error, Job, Result};
use serde_json::{json, Value};
use std::{
    fs::{self, File, Metadata},
    io::{BufReader, Read, Write},
    path::Path,
    str::FromStr,
};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;

pub fn generate_key(output: &Path) -> Result<Value> {
    let identity = x25519::Identity::generate();
    let secret = identity.to_string();
    // Keep the private text in age's zeroizing secret-string wrapper until it is
    // written to a new, private temporary file by Localwright's no-clobber writer.
    let file_text = SecretString::from(format!("{}\n", secret.expose_secret()));
    write_bytes(output, file_text.expose_secret().as_bytes())?;
    Ok(json!({
        "schema_version": 1,
        "recipient": identity.to_public().to_string(),
        "private_key_file": output,
    }))
}

pub fn encrypt(input: &Path, output: &Path, recipient_text: &str, job: &Job) -> Result<Value> {
    let recipient = x25519::Recipient::from_str(recipient_text.trim())
        .map_err(|_| Error::input("Enter a valid age X25519 recipient key"))?;
    let (mut source, before) = open_regular(input)?;
    if before.len() > MAX_FILE_BYTES {
        return Err(Error::input("Input exceeds the 4 GiB encryption limit"));
    }
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as _))
        .map_err(|_| Error::engine("Could not initialize age encryption"))?;
    let mut total = 0_u64;
    write_new(output, |file| {
        let mut writer = encryptor
            .wrap_output(file)
            .map_err(|e| Error::engine(format!("Could not initialize age output: {e}")))?;
        let mut buffer = [0_u8; CHUNK_BYTES];
        loop {
            job.check()?;
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| Error::input("Input size overflow"))?;
            if total > MAX_FILE_BYTES || total > before.len() {
                return Err(Error::input("Input grew beyond the 4 GiB encryption limit"));
            }
            writer.write_all(&buffer[..count])?;
            job.progress(total, before.len());
        }
        finish_source(&source, &before, total)?;
        job.check()?;
        writer
            .finish()
            .map_err(|e| Error::engine(format!("Could not finalize age encryption: {e}")))?;
        Ok(())
    })?;
    Ok(json!({
        "schema_version": 1,
        "format": "age",
        "plaintext_bytes": total,
        "ciphertext_file": output,
    }))
}

pub fn decrypt(input: &Path, output: &Path, identity_path: &Path, job: &Job) -> Result<Value> {
    let identity = load_identity(identity_path)?;
    let (mut source, before) = open_regular(input)?;
    let source_guard = source.try_clone()?;
    if before.len() > MAX_FILE_BYTES + 1024 * 1024 {
        return Err(Error::input(
            "Encrypted input exceeds the 4 GiB processing limit",
        ));
    }
    let decryptor = Decryptor::new_buffered(BufReader::new(&mut source))
        .map_err(|_| Error::input("Input is not a valid age-encrypted file"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as _))
        .map_err(|_| Error::input("Age file could not be decrypted with this identity"))?;
    let mut total = 0_u64;
    // write_new only publishes the sibling temporary file after this closure
    // succeeds. age reports authentication failure while the stream is read to EOF,
    // so a damaged ciphertext never leaves partially decrypted output behind.
    write_new(output, |file| {
        let mut buffer = [0_u8; CHUNK_BYTES];
        loop {
            job.check()?;
            let count = reader.read(&mut buffer).map_err(|_| {
                Error::input("Could not read or authenticate age data; no plaintext was saved")
            })?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| Error::input("Decrypted size overflow"))?;
            if total > MAX_FILE_BYTES {
                return Err(Error::input("Decrypted output exceeds the 4 GiB limit"));
            }
            file.write_all(&buffer[..count])?;
            job.progress(total, 0);
        }
        finish_source(&source_guard, &before, before.len())?;
        job.check()?;
        Ok(())
    })?;
    Ok(json!({
        "schema_version": 1,
        "format": "age",
        "authenticated_plaintext_bytes": total,
        "plaintext_file": output,
    }))
}

fn open_regular(path: &Path) -> Result<(File, Metadata)> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Choose a regular, non-symlink file"));
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.len() != before.len()
        || opened.modified()? != before.modified()?
    {
        return Err(Error::input("Input changed while it was being opened"));
    }
    Ok((file, opened))
}

fn finish_source(file: &File, before: &Metadata, total: u64) -> Result<()> {
    let after = file.metadata()?;
    if total != before.len()
        || after.len() != before.len()
        || before.modified()? != after.modified()?
    {
        return Err(Error::input("Input changed while it was being processed"));
    }
    Ok(())
}

fn load_identity(path: &Path) -> Result<x25519::Identity> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::input("Identity must be a regular, non-symlink file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::input(
                "Identity file permissions are too broad; restrict access to its owner",
            ));
        }
    }
    let bytes = localwright_core::read_bounded(path, 64 * 1024)?;
    let content = SecretString::from(
        String::from_utf8(bytes)
            .map_err(|_| Error::input("Identity file must contain UTF-8 age key text"))?,
    );
    for line in content.expose_secret().lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(identity) = x25519::Identity::from_str(line) {
            return Ok(identity);
        }
    }
    Err(Error::input(
        "Identity file contains no valid age X25519 identity",
    ))
}
