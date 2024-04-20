pub mod aead;
pub mod buffer;
pub mod cipher_suite;
pub mod key_derivation;
pub mod secret;

cfg_if::cfg_if! {
if #[cfg(all(feature = "ring", not(feature = "openssl"), not(feature = "rust-crypto")))]{
    mod ring;
}
else if #[cfg(all(feature = "openssl", not(feature = "ring"), not(feature = "rust-crypto")))] {
    mod common;
    mod openssl;
}
else if #[cfg(all(feature = "rust-crypto", not(feature = "ring"), not(feature = "openssl")))] {
    mod common;
    mod rust_crypto;
} else {
    compile_error!("Cannot configure multiple crypto backends at the same time.");
}
}
