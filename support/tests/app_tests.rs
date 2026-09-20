use keyfile_core::{HEADER_LEN, MAC_LEN, Spec, open, seal};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const KEY: &[u8] = b"test-only random-looking fixture; never a deployed key";
fn payload(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(71).wrapping_add(i / 256)) as u8)
        .collect()
}

#[test]
fn binary_and_empty_roundtrips_at_block_boundaries() {
    for n in [
        0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 4095,
        4096, 65537,
    ] {
        let plain = payload(n);
        let encoded = seal::<App>(KEY, &plain).unwrap();
        assert_eq!(encoded.len(), HEADER_LEN + App::body_len(n) + MAC_LEN);
        assert_eq!(open::<App>(KEY, &encoded).unwrap().as_slice(), plain);
    }
}
#[test]
fn every_encryption_uses_fresh_salt_and_keys() {
    let a = seal::<App>(KEY, &[42; 500]).unwrap();
    let b = seal::<App>(KEY, &[42; 500]).unwrap();
    assert_ne!(a[20..52], b[20..52]);
    assert_ne!(a, b);
}
#[test]
fn wrong_key_is_rejected() {
    assert!(open::<App>(b"wrong", &seal::<App>(KEY, b"private").unwrap()).is_err());
}
#[test]
fn raw_key_file_bytes_accept_supported_lengths() {
    for n in [1, 16, 31, 32, 33, 255, 1024] {
        let key = payload(n);
        assert_eq!(
            open::<App>(&key, &seal::<App>(&key, b"message").unwrap())
                .unwrap()
                .as_slice(),
            b"message"
        );
    }
    assert!(seal::<App>(b"", b"data").is_err());
}
#[test]
fn every_header_byte_is_authenticated_or_strictly_parsed() {
    let encoded = seal::<App>(KEY, b"header test").unwrap();
    for i in 0..HEADER_LEN {
        let mut damaged = encoded.clone();
        damaged[i] ^= 1;
        assert!(open::<App>(KEY, &damaged).is_err(), "header byte {i}");
    }
}
#[test]
fn every_ciphertext_and_mac_byte_is_authenticated() {
    let encoded = seal::<App>(KEY, &payload(129)).unwrap();
    for i in HEADER_LEN..encoded.len() {
        let mut damaged = encoded.clone();
        damaged[i] ^= 128;
        assert!(open::<App>(KEY, &damaged).is_err(), "body/MAC byte {i}");
    }
}
#[test]
fn all_truncations_and_trailing_bytes_are_rejected() {
    let encoded = seal::<App>(KEY, &payload(65)).unwrap();
    for n in 0..encoded.len() {
        assert!(open::<App>(KEY, &encoded[..n]).is_err());
    }
    let mut appended = encoded.to_vec();
    appended.push(0);
    assert!(open::<App>(KEY, &appended).is_err());
}
#[test]
fn app_identifier_and_huge_declared_length_are_rejected() {
    let mut encoded = seal::<App>(KEY, b"message").unwrap();
    encoded[9..11].copy_from_slice(&(App::ID + 1).to_le_bytes());
    assert!(open::<App>(KEY, &encoded).is_err());
    encoded[9..11].copy_from_slice(&App::ID.to_le_bytes());
    encoded[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(open::<App>(KEY, &encoded).is_err());
}
#[test]
fn backend_rejects_wrong_key_size() {
    assert!(App::encrypt(&[], &[0; App::NONCE_LEN], b"aad", b"data").is_err());
    assert!(App::decrypt(&[], &[0; App::NONCE_LEN], b"aad", b"data").is_err());
}

// Unix fork can briefly inherit another test's writable executable descriptor,
// even with CLOEXEC, until exec closes it. Coordinate copies with process starts.
// https://github.com/rust-lang/rust/issues/114554
static PROCESS_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    dir: tempfile::TempDir,
    cwd: tempfile::TempDir,
    exe: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let _guard = PROCESS_GATE.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let exe = dir.path().join(Path::new(EXE).file_name().unwrap());
        fs::copy(EXE, &exe).unwrap();
        fs::write(dir.path().join("key.key"), KEY).unwrap();
        fs::write(dir.path().join("plain.bin"), payload(1025)).unwrap();
        Self { dir, cwd, exe }
    }
    fn run(&self, args: &[&str]) -> Output {
        let child = {
            let _guard = PROCESS_GATE.lock().unwrap();
            Command::new(&self.exe)
                .args(args)
                .current_dir(self.cwd.path())
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        };
        child.wait_with_output().unwrap()
    }
    fn ok(&self, args: &[&str]) {
        let o = self.run(args);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    fn fail(&self, args: &[&str]) {
        let o = self.run(args);
        assert!(!o.status.success(), "unexpected success: {args:?}");
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }
}

#[test]
fn cli_uses_executable_directory_even_from_another_cwd() {
    let f = Fixture::new();
    fs::write(f.cwd.path().join("key.key"), b"wrong cwd key").unwrap();
    fs::write(f.cwd.path().join("plain.bin"), b"wrong cwd plaintext").unwrap();
    f.ok(&["E", "plain.bin", "sealed.bin"]);
    f.ok(&["D", "sealed.bin", "restored.bin"]);
    assert_eq!(fs::read(f.path("restored.bin")).unwrap(), payload(1025));
    assert_eq!(fs::read(f.path("plain.bin")).unwrap(), payload(1025));
    assert_eq!(fs::read(f.path("key.key")).unwrap(), KEY);
    assert!(!f.cwd.path().join("sealed.bin").exists());
}
#[test]
fn cli_supports_unicode_names_spaces_and_empty_files() {
    let f = Fixture::new();
    fs::write(f.path("空 file.bin"), []).unwrap();
    f.ok(&["E", "空 file.bin", "encrypted file.bin"]);
    f.ok(&["D", "encrypted file.bin", "戻 file.bin"]);
    assert!(fs::read(f.path("戻 file.bin")).unwrap().is_empty());
}
#[test]
fn cli_missing_key_does_not_fall_back_to_cwd_or_create_output() {
    let f = Fixture::new();
    fs::remove_file(f.path("key.key")).unwrap();
    fs::write(f.cwd.path().join("key.key"), KEY).unwrap();
    f.fail(&["E", "plain.bin", "out.bin"]);
    assert!(!f.path("out.bin").exists());
}
#[test]
fn cli_empty_key_is_rejected_without_output() {
    let f = Fixture::new();
    fs::write(f.path("key.key"), []).unwrap();
    f.fail(&["E", "plain.bin", "out.bin"]);
    assert!(!f.path("out.bin").exists());
}
#[test]
fn cli_existing_outputs_and_input_are_never_overwritten() {
    let f = Fixture::new();
    fs::write(f.path("existing.bin"), b"keep").unwrap();
    f.fail(&["E", "plain.bin", "existing.bin"]);
    f.fail(&["E", "plain.bin", "plain.bin"]);
    f.ok(&["E", "plain.bin", "sealed.bin"]);
    f.fail(&["D", "sealed.bin", "existing.bin"]);
    assert_eq!(fs::read(f.path("existing.bin")).unwrap(), b"keep");
    assert_eq!(fs::read(f.path("plain.bin")).unwrap(), payload(1025));
}
#[test]
fn cli_rejects_path_traversal_absolute_paths_ads_and_device_names() {
    let f = Fixture::new();
    for bad in [
        "../outside",
        "..\\outside",
        "sub/file",
        "sub\\file",
        "C:\\outside",
        "/outside",
        "plain.bin:stream",
        ".",
        "..",
        "NUL",
        "CON.txt",
        "LPT1",
        "COM¹",
        "trailing.",
        "trailing ",
    ] {
        f.fail(&["E", "plain.bin", bad]);
        f.fail(&["E", bad, "out.bin"]);
    }
    assert!(!f.path("out.bin").exists());
}
#[test]
fn cli_key_and_executable_cannot_be_used_as_input_or_output() {
    let f = Fixture::new();
    for protected in [
        "key.key",
        "KEY.KEY",
        f.exe.file_name().unwrap().to_str().unwrap(),
    ] {
        f.fail(&["E", protected, "out.bin"]);
        f.fail(&["E", "plain.bin", protected]);
    }
    assert_eq!(fs::read(f.path("key.key")).unwrap(), KEY);
    assert!(!f.path("out.bin").exists());
}
#[test]
fn cli_wrong_key_leaves_no_output_or_temporary_files() {
    let f = Fixture::new();
    f.ok(&["E", "plain.bin", "sealed.bin"]);
    fs::write(f.path("key.key"), b"wrong key").unwrap();
    f.fail(&["D", "sealed.bin", "out.bin"]);
    assert!(!f.path("out.bin").exists());
    assert!(
        !fs::read_dir(f.dir.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp"))
    );
}
#[test]
fn cli_tampered_ciphertext_does_not_publish_plaintext() {
    let f = Fixture::new();
    f.ok(&["E", "plain.bin", "sealed.bin"]);
    let mut encoded = fs::read(f.path("sealed.bin")).unwrap();
    encoded[HEADER_LEN] ^= 1;
    fs::write(f.path("sealed.bin"), encoded).unwrap();
    f.fail(&["D", "sealed.bin", "out.bin"]);
    assert!(!f.path("out.bin").exists());
}
#[test]
fn cli_requires_exact_command_shape_and_existing_regular_input() {
    let f = Fixture::new();
    for args in [
        vec![],
        vec!["E"],
        vec!["E", "plain.bin"],
        vec!["encrypt", "plain.bin", "out.bin"],
        vec!["E", "plain.bin", "out.bin", "extra"],
        vec!["E", "missing", "out.bin"],
    ] {
        f.fail(&args);
    }
    fs::create_dir(f.path("directory")).unwrap();
    f.fail(&["E", "directory", "out.bin"]);
    assert!(!f.path("out.bin").exists());
}

#[cfg(unix)]
#[test]
fn cli_rejects_symlink_inputs_keys_and_outputs() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    symlink(f.path("plain.bin"), f.path("link.bin")).unwrap();
    f.fail(&["E", "link.bin", "out.bin"]);
    symlink(f.path("missing"), f.path("out.bin")).unwrap();
    f.fail(&["E", "plain.bin", "out.bin"]);
    fs::remove_file(f.path("key.key")).unwrap();
    symlink(f.path("plain.bin"), f.path("key.key")).unwrap();
    f.fail(&["E", "plain.bin", "another.bin"]);
}
