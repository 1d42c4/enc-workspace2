use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = eax::Eax<twofish::Twofish>;
impl Spec for App {
    const ID: u16 = 25;
    const NAME: &str = "Twofish-256-EAX";
    const CATEGORY: &str = "composed / experimental";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 16;
    fn body_len(n: usize) -> usize {
        n + 16
    }
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        encrypt(key, nonce, aad, data)
    }
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(key, nonce, aad, data)
    }
}
include!("../../../support/backends/aead.rs");

#[cfg(test)]
mod primitive_known_answer {

    #[test]
    fn published_block_vector() {
        use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
        type Primitive = twofish::Twofish;
        let key: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let plain: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let expected: &[u8] = &[
            0x57, 0xff, 0x73, 0x9d, 0x4d, 0xc9, 0x2c, 0x1b, 0xd7, 0xfc, 0x01, 0x70, 0x0c, 0xc8,
            0x21, 0x6f,
        ];
        let engine = Primitive::new_from_slice(key).unwrap();
        let mut block = Block::<Primitive>::try_from(plain).unwrap();
        engine.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), expected);
        engine.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), plain);
    }
}
