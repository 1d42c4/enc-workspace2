//! Versioned authenticated file envelopes and executable-local file handling.
//! This workspace is not an externally audited encryption product.
mod private_file;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};
use zeroize::Zeroizing;

pub type Result<T> = io::Result<T>;
pub const MAX_PLAIN: usize = 64 * 1024 * 1024;
pub const MAX_KEY: usize = 1024 * 1024;
pub const HEADER_LEN: usize = 64;
pub const MAC_LEN: usize = 32;
const MAGIC: &[u8; 8] = b"ENCWS2\r\n";

/// A concrete application fixes its algorithm and key/nonce sizes at compile time.
pub trait Spec {
    const ID: u16;
    const NAME: &'static str;
    const CATEGORY: &'static str;
    const KEY_LEN: usize;
    const NONCE_LEN: usize;
    fn body_len(plain_len: usize) -> usize;
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plain: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], body: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

pub fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid file, wrong key, or authentication failed",
    )
}
fn error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn material<S: Spec>(key: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.is_empty() || key.len() > MAX_KEY {
        return Err(error(
            "key.key must contain 1 to 1048576 bytes; prefer 32 random bytes",
        ));
    }
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(key)));
    let mut info = b"enc-workspace2/v1/keys/".to_vec();
    info.extend_from_slice(&S::ID.to_le_bytes());
    let mut output = Zeroizing::new(vec![0u8; S::KEY_LEN + S::NONCE_LEN + 32]);
    Hkdf::<Sha256>::new(Some(salt), digest.as_ref())
        .expand(&info, &mut output)
        .map_err(|_| invalid())?;
    Ok(output)
}

/// Seal a complete plaintext. A fresh 256-bit salt separates keys for every file.
pub fn seal<S: Spec>(key: &[u8], plain: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if plain.len() > MAX_PLAIN {
        return Err(error("input exceeds the 64 MiB plaintext limit"));
    }
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8] = 1;
    header[9..11].copy_from_slice(&S::ID.to_le_bytes());
    header[12..20].copy_from_slice(&(plain.len() as u64).to_le_bytes());
    getrandom::fill(&mut header[20..52]).map_err(io::Error::other)?;
    let keys = material::<S>(key, &header[20..52])?;
    let (cipher_key, rest) = keys.split_at(S::KEY_LEN);
    let (nonce, mac_key) = rest.split_at(S::NONCE_LEN);
    let body = S::encrypt(cipher_key, nonce, &header, plain)?;
    if body.len() != S::body_len(plain.len()) {
        return Err(invalid());
    }
    let mut output = Zeroizing::new(Vec::with_capacity(HEADER_LEN + body.len() + MAC_LEN));
    output.extend_from_slice(&header);
    output.extend_from_slice(&body);
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| invalid())?;
    mac.update(&output);
    output.extend_from_slice(&mac.finalize().into_bytes());
    Ok(output)
}

/// Verify the complete envelope before calling a cipher or exposing plaintext.
pub fn open<S: Spec>(key: &[u8], encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if encoded.len() < HEADER_LEN + MAC_LEN
        || encoded.len() > S::body_len(MAX_PLAIN) + HEADER_LEN + MAC_LEN
    {
        return Err(invalid());
    }
    let header = &encoded[..HEADER_LEN];
    if &header[..8] != MAGIC
        || header[8] != 1
        || header[9..11] != S::ID.to_le_bytes()
        || header[11] != 0
        || header[52..].iter().any(|&b| b != 0)
    {
        return Err(invalid());
    }
    let len = u64::from_le_bytes(header[12..20].try_into().map_err(|_| invalid())?);
    let len = usize::try_from(len).map_err(|_| invalid())?;
    if len > MAX_PLAIN || encoded.len() != HEADER_LEN + S::body_len(len) + MAC_LEN {
        return Err(invalid());
    }
    let keys = material::<S>(key, &header[20..52])?;
    let (cipher_key, rest) = keys.split_at(S::KEY_LEN);
    let (nonce, mac_key) = rest.split_at(S::NONCE_LEN);
    let signed_len = encoded.len() - MAC_LEN;
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| invalid())?;
    mac.update(&encoded[..signed_len]);
    mac.verify_slice(&encoded[signed_len..])
        .map_err(|_| invalid())?;
    let plain = S::decrypt(cipher_key, nonce, header, &encoded[HEADER_LEN..signed_len])?;
    if plain.len() != len {
        return Err(invalid());
    }
    Ok(plain)
}

/// Require exactly one portable, ordinary filename, including on Unix.
pub fn validate_name(name: &OsStr) -> Result<()> {
    let name = name
        .to_str()
        .ok_or_else(|| error("filenames must be valid Unicode"))?;
    let path = Path::new(name);
    if name.is_empty()
        || name.len() > 200
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:<>\"|?*".contains(c))
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(error(
            "use a plain filename beside the executable, without folders or special characters",
        ));
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix)
            .is_some_and(|s| s.chars().count() == 1 && "123456789¹²³".contains(s))
    });
    if reserved {
        return Err(error("Windows device names are not ordinary filenames"));
    }
    Ok(())
}

fn ordinary(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0
    }
    #[cfg(not(windows))]
    {
        metadata.is_file() && !metadata.file_type().is_symlink()
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !ordinary(&fs::symlink_metadata(path)?) {
        return Err(error(
            "input and key must be ordinary files, not links or directories",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself if another process replaces the path.
        options.custom_flags(0x0020_0000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !ordinary(&metadata) {
        return Err(error("input and key must be ordinary files"));
    }
    if metadata.len() > limit as u64 {
        return Err(error("file exceeds the supported size limit"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(error("file exceeds the supported size limit"));
    }
    Ok(bytes)
}

fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "output already exists; choose a new filename",
        )),
    }
}

fn publish(path: &Path, bytes: &[u8]) -> Result<File> {
    absent(path)?;
    let parent = path.parent().ok_or_else(invalid)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".encws2-")
        .suffix(".tmp")
        .make_in(parent, private_file::create_private)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    let file = temp.persist_noclobber(path).map_err(|e| e.error)?;
    Ok(file)
}

/// Create a fresh key only when key.key does not already exist.
pub fn generate_key(directory: &Path) -> Result<()> {
    let directory = directory.canonicalize()?;
    if !directory.is_dir() {
        return Err(error("key destination must be an existing directory"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut()).map_err(io::Error::other)?;
    publish(&directory.join("key.key"), key.as_ref())?;
    Ok(())
}

fn execute<S: Spec>(args: &[std::ffi::OsString], executable: &Path) -> Result<PathBuf> {
    if args.len() != 3 || (args[0] != "E" && args[0] != "D") {
        return Err(error("expected E or D, input filename, output filename"));
    }
    validate_name(&args[1])?;
    validate_name(&args[2])?;
    let exe_name = executable
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(invalid)?;
    for name in [&args[1], &args[2]] {
        let name = name.to_str().ok_or_else(invalid)?;
        if name.eq_ignore_ascii_case("key.key") || name.eq_ignore_ascii_case(exe_name) {
            return Err(error(
                "key.key and the executable cannot be input or output",
            ));
        }
    }
    if args[1]
        .to_string_lossy()
        .eq_ignore_ascii_case(&args[2].to_string_lossy())
    {
        return Err(error("input and output names must differ"));
    }
    let directory = executable.parent().ok_or_else(invalid)?;
    let output = directory.join(&args[2]);
    absent(&output)?;
    let key = read_bounded(&directory.join("key.key"), MAX_KEY)?;
    if key.is_empty() {
        return Err(error("key.key is empty"));
    }
    let encrypt = args[0] == "E";
    let limit = if encrypt {
        MAX_PLAIN
    } else {
        S::body_len(MAX_PLAIN) + HEADER_LEN + MAC_LEN
    };
    let input = read_bounded(&directory.join(&args[1]), limit)?;
    let result = if encrypt {
        seal::<S>(&key, &input)?
    } else {
        open::<S>(&key, &input)?
    };
    publish(&output, &result)?;
    Ok(output)
}

pub fn run<S: Spec>() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .and_then(|p| execute::<S>(&args, &p));
    match result {
        Ok(output) => {
            println!("Created {}", output.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "a{}: {} [{}]\nError: {e}\nUsage: a{} E input-name output-name\n       a{} D input-name output-name\nkey.key and both files belong beside this executable. Output must be new.",
                S::ID,
                S::NAME,
                S::CATEGORY,
                S::ID,
                S::ID
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
