fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        eprintln!(
            "Usage: keygen <existing-app-directory> (creates a new random key.key; never overwrites)"
        );
        return std::process::ExitCode::FAILURE;
    }
    match keyfile_core::generate_key(std::path::Path::new(&args[0])) {
        Ok(()) => {
            println!("Created key.key. Keep a separate safe backup.");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
