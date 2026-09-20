// EAX needs Clone. Share the immutable RustCrypto key schedule; its Drop still
// zeroizes it when the final owner is dropped. No cipher algorithm is reimplemented.
#[derive(Clone)]
struct Rc6_256(std::sync::Arc<rc6::RC6<u32, cipher::consts::U20, cipher::consts::U32>>);
impl cipher::KeySizeUser for Rc6_256 {
    type KeySize = cipher::consts::U32;
}
impl cipher::BlockSizeUser for Rc6_256 {
    type BlockSize = cipher::consts::U16;
}
impl cipher::KeyInit for Rc6_256 {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self(std::sync::Arc::new(rc6::RC6::new(key)))
    }
}
impl cipher::BlockCipherEncrypt for Rc6_256 {
    fn encrypt_with_backend(
        &self,
        f: impl cipher::BlockCipherEncClosure<BlockSize = Self::BlockSize>,
    ) {
        self.0.encrypt_with_backend(f);
    }
}
impl cipher::BlockCipherDecrypt for Rc6_256 {
    fn decrypt_with_backend(
        &self,
        f: impl cipher::BlockCipherDecClosure<BlockSize = Self::BlockSize>,
    ) {
        self.0.decrypt_with_backend(f);
    }
}
