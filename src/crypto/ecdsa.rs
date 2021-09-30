// This file is part of TRINCI.
//
// Copyright (C) 2021 Affidaty Spa.
//
// TRINCI is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// TRINCI is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with TRINCI. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    crypto::{Hash, HashAlgorithm},
    Error, ErrorKind, Result,
};
use ring::{
    rand::SystemRandom,
    signature::{
        self, EcdsaKeyPair as EcdsaKeyPairImpl, KeyPair as RingKeyPair,
        UnparsedPublicKey as RingPublicKey,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct KeyPair {
    imp: EcdsaKeyPairImpl,
    rng: SystemRandom,
}

impl KeyPair {
    pub fn new(private_bytes: &[u8], public_bytes: &[u8]) -> Result<KeyPair> {
        let imp = EcdsaKeyPairImpl::from_private_key_and_public_key(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            private_bytes,
            public_bytes,
        )
        .map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))?;
        Ok(KeyPair {
            imp,
            rng: SystemRandom::new(),
        })
    }

    pub fn from_pkcs8_bytes(bytes: &[u8]) -> Result<KeyPair> {
        let imp = EcdsaKeyPairImpl::from_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, bytes)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        Ok(KeyPair {
            imp,
            rng: SystemRandom::new(),
        })
    }

    /// ECDSA P-384 digital signature generation.
    /// `public_key`, `private_key` are expected in Base58.
    /// Returns the data digital signature in Base58.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .imp
            .sign(&self.rng, data)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?
            .as_ref()
            .to_vec();
        Ok(sig)
    }

    pub fn public_key(&self) -> PublicKey {
        let public = self.imp.public_key().as_ref().to_vec();
        PublicKey {
            curve: CurveId::Secp384R1,
            value: public,
        }
    }
}

crate::named_unit_variant!(secp384r1);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(untagged)]
pub enum CurveId {
    #[serde(with = "secp384r1")]
    Secp384R1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PublicKey {
    pub curve: CurveId,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl PublicKey {
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        let imp = RingPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &self.value);
        imp.verify(data, sig).is_ok()
    }

    pub fn to_account_id(&self) -> String {
        let bytes = self.value.to_owned();
        let bytes = add_asn1_x509_header(bytes);
        let bytes = add_protobuf_header(bytes);

        let hash = Hash::from_data(HashAlgorithm::Sha256, &bytes);

        bs58::encode(hash).into_string()
    }
}

// ASN1 header.
// WARNING: this is an ad-hoc rough implementation for secp384r1.
#[rustfmt::skip]
fn add_asn1_x509_header(mut key_bytes: Vec<u8>) -> Vec<u8> {
    let mut res: Vec<u8> = vec![
        // ASN.1 struct type and length.
        0x30, 0x76,
        // ASN.1 struct type and length.
        0x30, 0x10,
        // OID: 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        // OID: 1.3.132.0.34 secp384r1 (SECG named elliptic curve)
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
        // Bitstring (type and length)
        0x03, 0x62, 0x00,
    ];
    res.append(&mut key_bytes);
    res
}

// Protobuf header.
// This is compatible with libp2p specification.
// WARNING: this is an ad-hoc rough implementation for ECDSA.
#[rustfmt::skip]
fn add_protobuf_header(mut buf: Vec<u8>) -> Vec<u8> {
    let mut res: Vec<u8> = vec![
        // Algorithm type tag.
        0x08,
        // ECDSA.
        0x03,
        // Length tag.
        0x12,
        // Payload length.
        buf.len() as u8,
    ];
    res.append(&mut buf);
    res
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::base::serialize::{rmp_deserialize, rmp_serialize};

    const PRIVATE_KEY_BYTES: &str = "818f1a16382f219b9284442687420caa12a60d8945c93dca6d28e81f1597e6d8abcec81a2dca0fe6eae838891c1b7157";
    const PUBLIC_KEY_BYTES: &str = "045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1";
    const PUBLIC_KEY_HEX: &str = "92a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1";

    pub fn ecdsa_secp384_test_keypair() -> KeyPair {
        let private_bytes = hex::decode(PRIVATE_KEY_BYTES).unwrap();
        let public_bytes = hex::decode(PUBLIC_KEY_BYTES).unwrap();
        KeyPair::new(&private_bytes, &public_bytes).unwrap()
    }

    pub fn ecdsa_secp384_test_public_key() -> PublicKey {
        ecdsa_secp384_test_keypair().public_key()
    }

    #[test]
    fn ecdsa_secp384r1_to_account_id() {
        let public_key = ecdsa_secp384_test_public_key();

        let account_id = public_key.to_account_id();

        assert_eq!(account_id, "QmYHnEQLdf5h7KYbjFPuHSRk2SPgdXrJWFh5W696HPfq7i");
    }

    #[test]
    fn public_key_serialize() {
        let public_key = ecdsa_secp384_test_public_key();

        let buf = rmp_serialize(&public_key).unwrap();

        assert_eq!(hex::encode(&buf), PUBLIC_KEY_HEX);
    }

    #[test]
    fn public_key_deserialize() {
        let buf = hex::decode(PUBLIC_KEY_HEX).unwrap();

        let public_key: PublicKey = rmp_deserialize(&buf).unwrap();

        let expected = ecdsa_secp384_test_public_key();
        assert_eq!(public_key, expected);
    }
}
