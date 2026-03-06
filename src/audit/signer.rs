use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// AuditSigner -- Ed25519 signing and verification for audit records.
// ---------------------------------------------------------------------------

/// Signs and verifies audit records using Ed25519.
///
/// Each `AuditSigner` holds a single Ed25519 signing key (which includes the
/// corresponding verifying/public key).  The public key can be distributed to
/// downstream consumers that need to verify the integrity of audit records
/// without the ability to forge new signatures.
pub struct AuditSigner {
    signing_key: SigningKey,
}

impl AuditSigner {
    /// Generate a new random Ed25519 keypair.
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Reconstruct a signer from existing secret key bytes.
    ///
    /// `secret` must be exactly 32 bytes (the Ed25519 secret scalar).
    pub fn from_bytes(secret: &[u8]) -> Result<Self, String> {
        if secret.len() != 32 {
            return Err(format!(
                "Expected 32 secret key bytes, got {}",
                secret.len()
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(secret);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok(Self { signing_key })
    }

    /// Sign arbitrary data and return the signature as a lowercase hex string.
    pub fn sign(&self, data: &str) -> String {
        let signature: Signature = self.signing_key.sign(data.as_bytes());
        hex::encode(&signature.to_bytes())
    }

    /// Verify a hex-encoded signature against the given data.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise (including
    /// if the hex decoding fails or the signature length is wrong).
    pub fn verify(&self, data: &str, signature_hex: &str) -> bool {
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        verifying_key.verify(data.as_bytes(), &signature).is_ok()
    }

    /// Return the public (verifying) key as a lowercase hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.signing_key.verifying_key().to_bytes())
    }

    /// Return the secret key bytes (32 bytes).
    ///
    /// Treat the return value as sensitive material.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl Default for AuditSigner {
    fn default() -> Self {
        Self::new()
    }
}

// Hex encoding helper -- thin wrapper so we don't need the `hex` crate at the
// public API level (though we do use it internally for convenience).
mod hex {
    /// Encode bytes as a lowercase hex string.
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Decode a hex string into bytes.
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(2) {
            return Err("Odd-length hex string".into());
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks(2) {
            let hi = hex_digit(chunk[0])?;
            let lo = hex_digit(chunk[1])?;
            bytes.push((hi << 4) | lo);
        }
        Ok(bytes)
    }

    fn hex_digit(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(format!("Invalid hex digit: {}", b as char)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let signer = AuditSigner::new();
        let data = "audit event payload";
        let sig = signer.sign(data);
        assert!(signer.verify(data, &sig));
    }

    #[test]
    fn test_verify_tampered_data() {
        let signer = AuditSigner::new();
        let sig = signer.sign("original data");
        assert!(!signer.verify("tampered data", &sig));
    }

    #[test]
    fn test_verify_bad_hex() {
        let signer = AuditSigner::new();
        assert!(!signer.verify("data", "not_hex!!!"));
    }

    #[test]
    fn test_verify_wrong_length() {
        let signer = AuditSigner::new();
        assert!(!signer.verify("data", "abcd"));
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let signer1 = AuditSigner::new();
        let secret = signer1.secret_key_bytes();
        let signer2 = AuditSigner::from_bytes(&secret).unwrap();

        assert_eq!(signer1.public_key_hex(), signer2.public_key_hex());

        let data = "test roundtrip";
        let sig = signer1.sign(data);
        assert!(signer2.verify(data, &sig));
    }

    #[test]
    fn test_from_bytes_wrong_length() {
        let result = AuditSigner::from_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_hex_format() {
        let signer = AuditSigner::new();
        let pk = signer.public_key_hex();
        // Ed25519 public key is 32 bytes = 64 hex chars.
        assert_eq!(pk.len(), 64);
        assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_signature_hex_format() {
        let signer = AuditSigner::new();
        let sig = signer.sign("anything");
        // Ed25519 signature is 64 bytes = 128 hex chars.
        assert_eq!(sig.len(), 128);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
