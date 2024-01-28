pub mod aead;
pub mod cipher_suite;
pub mod key_derivation;
pub mod sframe_key;

cfg_if::cfg_if! {
if #[cfg(all(not(feature = "openssl"), feature = "ring"))]{
    mod ring;
}
else if #[cfg(all(feature = "openssl", not(feature = "ring")))] {
    mod openssl;
} else {
    compile_error!("Cannot configure multiple crypto backends at the same time.");
    mod ring;
}
}
