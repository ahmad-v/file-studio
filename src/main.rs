#![forbid(unsafe_code)]
#[cfg(feature = "gui")]
mod ui;

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("--cli") {
        args.remove(0);
        let result = if let Some(request) = sensitive_cli_request(&args) {
            request.and_then(|request| {
                let outcome = file_studio::handle(request, localwright_core::Job::new())?;
                println!("{}", serde_json::to_string_pretty(&outcome)?);
                Ok(())
            })
        } else {
            localwright_core::cli(args, file_studio::OPERATIONS, file_studio::handle)
        };
        if let Err(e) = result {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(feature = "gui")]
    if let Err(e) = ui::run_app(file_studio::OPERATIONS, file_studio::handle_workspace) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    #[cfg(not(feature = "gui"))]
    {
        eprintln!("Built without GUI; use --cli --help");
        std::process::exit(2);
    }
}

/// Read private-key passphrases from a no-echo terminal prompt, never argv.
/// The ordinary shared CLI remains in use for non-sensitive operations.
fn sensitive_cli_request(
    args: &[String],
) -> Option<localwright_core::Result<localwright_core::Request>> {
    use localwright_core::Request;

    let operation = args.first()?.as_str();
    let mut request = Request {
        operation: operation.to_owned(),
        ..Request::default()
    };
    match operation {
        "signature-keygen" => {
            request.output = args.get(2)?.into();
            if !args.get(1).is_some_and(String::is_empty) {
                return Some(Err(localwright_core::Error::input(
                    "Use an empty input argument for signature-keygen",
                )));
            }
        }
        "signature-protect-key" | "signature-export-public" => {
            request.input = args.get(1)?.into();
            request.output = args.get(2)?.into();
        }
        "signature-create" => {
            request.input = args.get(1)?.into();
            request.output = args.get(2)?.into();
            request.draft = args.get(3)?.clone();
        }
        _ => return None,
    }
    Some(
        rpassword::prompt_password("Private-key passphrase: ")
            .map_err(|_| {
                localwright_core::Error::input("Could not read passphrase from the terminal")
            })
            .map(|passphrase| {
                request.parameter = passphrase;
                request
            }),
    )
}
