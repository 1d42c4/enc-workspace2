// The crate's default KeySize is 16 despite supporting 32 bytes in new_from_slice.
// Bind the full 256-bit size for generic EAX/CCM/CTR/CBC constructors.
#[derive(Clone)]
struct Serpent256(serpent::Serpent);
impl cipher::KeySizeUser for Serpent256 {
    type KeySize = cipher::consts::U32;
}
impl cipher::BlockSizeUser for Serpent256 {
    type BlockSize = cipher::consts::U16;
}
impl cipher::KeyInit for Serpent256 {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self(
            <serpent::Serpent as cipher::KeyInit>::new_from_slice(key)
                .expect("32-byte Serpent key"),
        )
    }
}
impl cipher::BlockCipherEncrypt for Serpent256 {
    fn encrypt_with_backend(
        &self,
        f: impl cipher::BlockCipherEncClosure<BlockSize = Self::BlockSize>,
    ) {
        self.0.encrypt_with_backend(f);
    }
}
impl cipher::BlockCipherDecrypt for Serpent256 {
    fn decrypt_with_backend(
        &self,
        f: impl cipher::BlockCipherDecClosure<BlockSize = Self::BlockSize>,
    ) {
        self.0.decrypt_with_backend(f);
    }
}
