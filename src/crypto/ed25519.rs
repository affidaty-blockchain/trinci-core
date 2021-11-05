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
use ed25519_dalek::{
    Keypair as KeyPairImpl, PublicKey as PublicKeyImpl, Signer as _, Verifier as _,
};
use rand::rngs::OsRng;
use serde::{self, de::Visitor, Deserialize, Serialize};
use std::convert::TryFrom;

pub struct KeyPair(KeyPairImpl);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    imp: PublicKeyImpl,
}

impl KeyPair {
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyPair> {
        let internal = KeyPairImpl::from_bytes(bytes)
            .map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))?;
        Ok(KeyPair(internal))
    }

    pub fn from_random() -> KeyPair {
        let mut csprng = OsRng {};
        let internal = KeyPairImpl::generate(&mut csprng);
        KeyPair(internal)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = self.0.sign(data).to_bytes().to_vec();
        Ok(sig)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey { imp: self.0.public }
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey> {
        let internal = PublicKeyImpl::from_bytes(bytes)
            .map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))?;
        Ok(PublicKey { imp: internal })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.imp.to_bytes().to_vec()
    }

    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        ed25519_dalek::Signature::try_from(sig)
            .and_then(|s| self.imp.verify(data, &s))
            .is_ok()
    }

    pub fn to_account_id(&self) -> String {
        let bytes = self.to_bytes();
        let bytes = add_protobuf_header(bytes);
        let hash = Hash::from_data(HashAlgorithm::Identity, &bytes);
        bs58::encode(hash).into_string()
    }
}

// Protobuf header.
#[rustfmt::skip]
fn add_protobuf_header(mut buf: Vec<u8>) -> Vec<u8> {
    let mut res: Vec<u8> = vec![
        // Algorithm type tag.
        0x08,
        // Ed25519.
        0x01,
        // Length tag.
        0x12,
        // Payload length.
        buf.len() as u8,
    ];
    res.append(&mut buf);
    res
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'v> Visitor<'v> for BytesVisitor {
            type Value = PublicKey;

            fn expecting(
                &self,
                fmt: &mut std::fmt::Formatter<'_>,
            ) -> std::result::Result<(), std::fmt::Error> {
                write!(fmt, "expecting byte array.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PublicKey::from_bytes(bytes)
                    .map_err(|_err| serde::de::Error::custom("Invalid multihash"))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }
        }
        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::base::serialize::{rmp_deserialize, rmp_serialize};

    const ED25519_BYTES_HEX: &str = "5fe6fc0f9274651d278798a4d86d9395ffdf4eff7361876f72201a130befb2c9587b8d516e9605a6ee57a19e2734f1ab3bb8b45e6062801dff3e6408d8594063";
    const ED25519_PUB_SER_BYTES_HEX: &str =
        "c420587b8d516e9605a6ee57a19e2734f1ab3bb8b45e6062801dff3e6408d8594063";

    pub fn ed25519_test_keypair() -> KeyPair {
        let bytes = hex::decode(ED25519_BYTES_HEX).unwrap();
        KeyPair::from_bytes(&bytes).unwrap()
    }

    pub fn ed25519_test_public_key() -> PublicKey {
        ed25519_test_keypair().public_key()
    }

    #[test]
    fn ed25519_to_account_id() {
        let public_key = ed25519_test_public_key();

        let account_id = public_key.to_account_id();

        assert_eq!(
            account_id,
            "12D3KooWFmmKJ7jXhTfoYDvKkPqe7s9pHH42iZdf2xRdM5ykma1p"
        );
    }

    #[test]
    fn ed25519_public_key_serialize() {
        let public = ed25519_test_public_key();

        let buf = rmp_serialize(&public).unwrap();

        assert_eq!(hex::encode(&buf), ED25519_PUB_SER_BYTES_HEX);
    }

    #[test]
    fn ed25519_public_key_deserialize() {
        let expected = ed25519_test_public_key();
        let buf = hex::decode(ED25519_PUB_SER_BYTES_HEX).unwrap();

        let public: PublicKey = rmp_deserialize(&buf).unwrap();

        assert_eq!(public, expected);
    }

    #[test]
    fn ed25519_keypair_random_generation_sign_test() {
        let keypair = KeyPair::from_random();
        let data = b"hello world";
        let sign = keypair.sign(data).unwrap();
        println!(
            "public key: {}",
            hex::encode(keypair.public_key().to_bytes())
        );
        println!("sign: {}", hex::encode(&sign));
        assert!(keypair.public_key().verify(data, &sign));
    }
}
