use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = ctr::Ctr64BE<camellia::Camellia256>;
impl Spec for App {
    const ID: u16 = 50;
    const NAME: &str = "CAMELLIA-256-CTR";
    const CATEGORY: &str = "established primitive";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 16;
    fn body_len(n: usize) -> usize {
        n
    }
    fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        encrypt(key, nonce, aad, data)
    }
    fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(key, nonce, aad, data)
    }
}
include!("../../../support/backends/stream.rs");

#[cfg(test)]
mod primitive_known_answer {

    #[test]
    fn published_block_vector() {
        use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
        type Primitive = camellia::Camellia256;
        let key: &[u8] = &[
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let plain: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let expected: &[u8] = &[
            0x21, 0x36, 0xfa, 0xbd, 0xa0, 0x91, 0xdf, 0xb5, 0x17, 0x1b, 0x94, 0xb8, 0xef, 0xbb,
            0x5d, 0x08,
        ];
        let engine = Primitive::new_from_slice(key).unwrap();
        let mut block = Block::<Primitive>::try_from(plain).unwrap();
        engine.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), expected);
        engine.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), plain);
    }
}
