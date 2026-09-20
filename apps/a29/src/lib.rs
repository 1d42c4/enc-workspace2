use keyfile_core::{Result, Spec, invalid};
use zeroize::Zeroizing;
pub struct App;
include!("../../../support/backends/rc6_256.rs");
type Engine = eax::Eax<Rc6_256>;
impl Spec for App {
    const ID: u16 = 29;
    const NAME: &str = "RC6-256-EAX";
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
        type Primitive = super::Rc6_256;
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
            0x8f, 0x5f, 0xbd, 0x05, 0x10, 0xd1, 0x5f, 0xa8, 0x93, 0xfa, 0x3f, 0xda, 0x6e, 0x85,
            0x7e, 0xc2,
        ];
        let engine = Primitive::new_from_slice(key).unwrap();
        let mut block = Block::<Primitive>::try_from(plain).unwrap();
        engine.encrypt_block(&mut block);
        assert_eq!(block.as_slice(), expected);
        engine.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), plain);
    }
}
