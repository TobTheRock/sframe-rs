use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // Exactly one crypto backend selected.
        ring_backend: { all(feature = "ring", not(feature = "openssl"), not(feature = "rust-crypto")) },
        openssl_backend: { all(feature = "openssl", not(feature = "ring"), not(feature = "rust-crypto")) },
        rust_crypto_backend: { all(feature = "rust-crypto", not(feature = "ring"), not(feature = "openssl")) },
        // Any crypto backend selected (otherwise only the generic traits are exposed).
        crypto_backend: { any(feature = "ring", feature = "openssl", feature = "rust-crypto") },
        // Backends supporting the AES-CTR cipher suites.
        aes_ctr: { any(feature = "openssl", feature = "rust-crypto") },
    }
}
