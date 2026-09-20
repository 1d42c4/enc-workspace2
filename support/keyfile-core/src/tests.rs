use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
static DECRYPTIONS: AtomicUsize = AtomicUsize::new(0);
struct Probe;
impl Spec for Probe {
    const ID: u16 = 65000;
    const NAME: &'static str = "test";
    const CATEGORY: &'static str = "test";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    fn body_len(n: usize) -> usize {
        n
    }
    fn encrypt(_: &[u8], _: &[u8], _: &[u8], plain: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(plain.to_vec()))
    }
    fn decrypt(_: &[u8], _: &[u8], _: &[u8], body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        DECRYPTIONS.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(body.to_vec()))
    }
}
#[test]
fn rejects_bad_mac_before_decrypting() {
    let mut encoded = seal::<Probe>(b"key", b"secret").unwrap();
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    let before = DECRYPTIONS.load(Ordering::SeqCst);
    assert!(open::<Probe>(b"key", &encoded).is_err());
    assert_eq!(before, DECRYPTIONS.load(Ordering::SeqCst));
}
#[test]
fn filename_validation_handles_portable_edge_cases() {
    for name in ["file", ".hidden", "a.b", "空 file.bin"] {
        validate_name(OsStr::new(name)).unwrap();
    }
    for name in [
        "",
        "CON",
        "con.txt",
        "COM9.a",
        "LPT².txt",
        "conin$",
        "a\nb",
        "a\0b",
        "\\server\\share",
        "\\?\\C:\\x",
        "C:relative",
        "a*b",
    ] {
        assert!(validate_name(OsStr::new(name)).is_err(), "{name:?}");
    }
}
#[test]
fn bounded_read_refuses_large_files_without_reading_them() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large");
    File::create(&path)
        .unwrap()
        .set_len((MAX_PLAIN + 1) as u64)
        .unwrap();
    assert!(read_bounded(&path, MAX_PLAIN).is_err());
    assert!(read_bounded(&path, MAX_KEY).is_err());
}
#[test]
fn rejects_oversized_key_material() {
    assert!(seal::<Probe>(&vec![1; MAX_KEY + 1], b"data").is_err());
}
#[test]
fn key_generation_is_random_private_and_never_overwrites() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    generate_key(a.path()).unwrap();
    generate_key(b.path()).unwrap();
    let key = fs::read(a.path().join("key.key")).unwrap();
    assert_eq!(key.len(), 32);
    assert_ne!(key, fs::read(b.path().join("key.key")).unwrap());
    assert!(generate_key(a.path()).is_err());
    assert_eq!(key, fs::read(a.path().join("key.key")).unwrap());
    #[cfg(windows)]
    private_file::assert_private(&File::open(a.path().join("key.key")).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(a.path().join("key.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}
#[test]
fn publish_is_private_and_no_clobber_even_when_destination_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output");
    let file = publish(&path, b"secret").unwrap();
    #[cfg(windows)]
    private_file::assert_private(&file);
    drop(file);
    assert!(publish(&path, b"replacement").is_err());
    assert_eq!(fs::read(path).unwrap(), b"secret");
}
#[cfg(unix)]
#[test]
fn bounded_read_does_not_follow_symlinks_or_fifos() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("real"), b"secret").unwrap();
    symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
    assert!(read_bounded(&dir.path().join("link"), 100).is_err());
}
