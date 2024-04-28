pub mod key_derivation {
    use crate::crypto::cipher_suite::CipherSuite;

    pub fn expand_subsecret(cipher_suite: &CipherSuite, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let aes_keysize = key.len() - cipher_suite.hash_len;
        let enc_key = key[..aes_keysize].to_vec();
        let auth_key = key[aes_keysize..].to_vec();

        (enc_key, auth_key)
    }
}
