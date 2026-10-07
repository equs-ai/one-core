use ct_codecs::{Base64, Base64UrlSafeNoPadding, Encoder};
use sha2::{Digest, Sha512};

use crate::{Hasher, HasherError};

pub struct SHA512;

impl Hasher for SHA512 {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError> {
        let mut hasher = Sha512::new();
        hasher.update(input);
        let result = hasher.finalize();

        Base64::encode_to_string(result).map_err(|_| HasherError::CouldNotHash)
    }

    fn hash_base64_url(&self, input: &[u8]) -> Result<String, HasherError> {
        let mut hasher = Sha512::new();
        hasher.update(input);
        let result = hasher.finalize();

        Base64UrlSafeNoPadding::encode_to_string(result).map_err(|_| HasherError::CouldNotHash)
    }

    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, HasherError> {
        let mut hasher = Sha512::new();
        hasher.update(input);
        Ok(hasher.finalize().to_vec())
    }
}
