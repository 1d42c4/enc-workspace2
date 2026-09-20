use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
type Engine = ctr::Ctr64BE<threefish::Threefish256>;
impl Spec for App {
    const ID: u16 = 87;
    const NAME: &str = "Threefish-256-CTR";
    const CATEGORY: &str = "composed / experimental";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 32;
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
        type Primitive = threefish::Threefish256;
        let key: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let plain: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let expected: &[u8] = &[
            0x84, 0xda, 0x2a, 0x1f, 0x8b, 0xea, 0xee, 0x94, 0x70, 0x66, 0xae, 0x3e, 0x31, 0x03,
            0xf1, 0xad, 0x53, 0x6d, 0xb1, 0xf4, 0xa1, 0x19, 0x24, 0x95, 0x11, 0x6b, 0x9f, 0x3c,
            0xe6, 0x13, 0x3f, 0xd8,
        ];
        let engine = Primitive::new_from_slice(key).unwrap();
        let mut block = Block::<Primitive>::try_from(plain).unwrap();
        engine.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), expected);
        engine.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), plain);
    }
}
