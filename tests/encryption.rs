use file_studio::{handle, OPERATIONS};
use localwright_core::{ErrorKind, Job, Request};
use serde_json::Value;
use std::{fs, path::PathBuf};

fn request(operation: &str, input: PathBuf, output: PathBuf, parameter: &str) -> Request {
    Request {
        operation: operation.into(),
        input,
        output,
        parameter: parameter.into(),
        ..Request::default()
    }
}

fn create_identity(directory: &std::path::Path, name: &str) -> (PathBuf, String) {
    let identity_path = directory.join(name);
    let outcome = handle(
        request("age-keygen", PathBuf::new(), identity_path.clone(), ""),
        Job::new(),
    )
    .unwrap();
    let report: Value = serde_json::from_str(&outcome.preview).unwrap();
    assert_eq!(outcome.written, Some(identity_path.clone()));
    let recipient = report["recipient"].as_str().unwrap().to_owned();
    let key_text = fs::read_to_string(&identity_path).unwrap();
    assert!(key_text.starts_with("AGE-SECRET-KEY-"));
    assert!(!outcome.preview.contains(&key_text.trim().to_owned()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&identity_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    (identity_path, recipient)
}

#[test]
fn age_keys_encrypts_and_decrypts_binary_streams() {
    assert!(OPERATIONS
        .iter()
        .any(|operation| operation.id == "age-keygen"));
    assert!(OPERATIONS
        .iter()
        .any(|operation| operation.id == "age-encrypt"));
    assert!(OPERATIONS
        .iter()
        .any(|operation| operation.id == "age-decrypt"));
    let directory = tempfile::tempdir().unwrap();
    let (identity, recipient) = create_identity(directory.path(), "identity.txt");
    let input = directory.path().join("input.bin");
    let encrypted = directory.path().join("input.age");
    let decrypted = directory.path().join("restored.bin");
    let payload = (0..210_123)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&input, &payload).unwrap();

    let outcome = handle(
        request("age-encrypt", input.clone(), encrypted.clone(), &recipient),
        Job::new(),
    )
    .unwrap();
    assert!(outcome.preview.contains("age"));
    assert_eq!(fs::read(&input).unwrap(), payload);
    assert!(fs::metadata(&encrypted).unwrap().len() > payload.len() as u64);

    let outcome = handle(
        request(
            "age-decrypt",
            encrypted,
            decrypted.clone(),
            identity.to_str().unwrap(),
        ),
        Job::new(),
    )
    .unwrap();
    assert!(outcome.preview.contains("authenticated_plaintext_bytes"));
    assert_eq!(fs::read(decrypted).unwrap(), payload);

    let empty = directory.path().join("empty.txt");
    let empty_age = directory.path().join("empty.age");
    let empty_plain = directory.path().join("empty-restored.txt");
    fs::write(&empty, []).unwrap();
    handle(
        request("age-encrypt", empty, empty_age.clone(), &recipient),
        Job::new(),
    )
    .unwrap();
    handle(
        request(
            "age-decrypt",
            empty_age,
            empty_plain.clone(),
            identity.to_str().unwrap(),
        ),
        Job::new(),
    )
    .unwrap();
    assert_eq!(fs::read(empty_plain).unwrap(), b"");
}

#[test]
fn wrong_identity_and_modified_ciphertext_never_publish_plaintext() {
    let directory = tempfile::tempdir().unwrap();
    let (first_identity, first_recipient) = create_identity(directory.path(), "first.txt");
    let (second_identity, _) = create_identity(directory.path(), "second.txt");
    let input = directory.path().join("input.txt");
    let encrypted = directory.path().join("input.age");
    fs::write(&input, b"private fixture text").unwrap();
    handle(
        request("age-encrypt", input, encrypted.clone(), &first_recipient),
        Job::new(),
    )
    .unwrap();

    let wrong_output = directory.path().join("wrong.txt");
    let error = handle(
        request(
            "age-decrypt",
            encrypted.clone(),
            wrong_output.clone(),
            second_identity.to_str().unwrap(),
        ),
        Job::new(),
    )
    .unwrap_err();
    assert!(error.message.contains("decrypted"));
    assert!(!wrong_output.exists());

    let mut bytes = fs::read(&encrypted).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&encrypted, bytes).unwrap();
    let tampered_output = directory.path().join("tampered.txt");
    assert!(handle(
        request(
            "age-decrypt",
            encrypted,
            tampered_output.clone(),
            first_identity.to_str().unwrap(),
        ),
        Job::new(),
    )
    .is_err());
    assert!(!tampered_output.exists());
}

#[test]
fn age_outputs_never_overwrite_existing_files() {
    let directory = tempfile::tempdir().unwrap();
    let (_, recipient) = create_identity(directory.path(), "identity.txt");
    let input = directory.path().join("input.txt");
    let output = directory.path().join("existing.age");
    fs::write(&input, b"source stays").unwrap();
    fs::write(&output, b"keep me").unwrap();
    assert!(handle(
        request("age-encrypt", input.clone(), output.clone(), &recipient),
        Job::new(),
    )
    .is_err());
    assert_eq!(fs::read(output).unwrap(), b"keep me");
    assert_eq!(fs::read(input).unwrap(), b"source stays");
}

#[test]
fn cancelled_age_job_does_not_create_an_output() {
    let directory = tempfile::tempdir().unwrap();
    let (_, recipient) = create_identity(directory.path(), "identity.txt");
    let input = directory.path().join("input.txt");
    let output = directory.path().join("cancelled.age");
    fs::write(&input, b"source stays").unwrap();
    let job = Job::new();
    job.cancel();
    let error = handle(
        request("age-encrypt", input, output.clone(), &recipient),
        job,
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert!(!output.exists());
}

#[test]
fn identity_files_with_broad_unix_permissions_are_refused() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let (identity, _) = create_identity(directory.path(), "identity.txt");
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644)).unwrap();
        let input = directory.path().join("input.age");
        let output = directory.path().join("plain.txt");
        fs::write(&input, b"not a real age file").unwrap();
        let error = handle(
            request(
                "age-decrypt",
                input,
                output.clone(),
                identity.to_str().unwrap(),
            ),
            Job::new(),
        )
        .unwrap_err();
        assert!(error.message.contains("permissions"));
        assert!(!output.exists());
    }
}

#[cfg(unix)]
#[test]
fn symlinked_encryption_input_is_rejected() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real.txt");
    let link = directory.path().join("linked.txt");
    let (_, recipient) = create_identity(directory.path(), "identity.txt");
    fs::write(&real, b"source").unwrap();
    symlink(&real, &link).unwrap();
    assert!(handle(
        request(
            "age-encrypt",
            link,
            directory.path().join("out.age"),
            &recipient,
        ),
        Job::new(),
    )
    .is_err());
}
