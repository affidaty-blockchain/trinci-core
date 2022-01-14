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
    crypto::{ecdsa, ed25519},
    Result,
};
use serde::{self, Deserialize, Serialize};

pub enum KeyPair {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
}

impl KeyPair {
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            KeyPair::Ecdsa(keypair) => keypair.sign(data),
            KeyPair::Ed25519(keypair) => keypair.sign(data),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            KeyPair::Ecdsa(keypair) => PublicKey::Ecdsa(keypair.public_key()),
            KeyPair::Ed25519(keypair) => PublicKey::Ed25519 {
                pb: keypair.public_key(),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "type")]
pub enum PublicKey {
    #[serde(rename = "ecdsa")]
    Ecdsa(ecdsa::PublicKey),
    #[serde(rename = "ed25519")]
    Ed25519 { pb: ed25519::PublicKey },
}

impl PublicKey {
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Ecdsa(key) => key.verify(data, sig),
            PublicKey::Ed25519 { pb } => pb.verify(data, sig),
        }
    }

    pub fn to_account_id(&self) -> String {
        match self {
            PublicKey::Ecdsa(key) => key.to_account_id(),
            PublicKey::Ed25519 { pb } => pb.to_account_id(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        base::serialize::{rmp_deserialize, rmp_serialize},
        crypto::{
            ecdsa::tests::{ecdsa_secp384_test_keypair, ecdsa_secp384_test_public_key},
            ed25519::tests::ed25519_test_public_key,
        },
    };

    const ECDSA_PUBLIC_KEY_SER_HEX: &str = "93a56563647361a9736563703338347231c461045936d631b849bb5760bcf62e0d1261b6b6e227dc0a3892cbeec91be069aaa25996f276b271c2c53cba4be96d67edcadd66b793456290609102d5401f413cd1b5f4130b9cfaa68d30d0d25c3704cb72734cd32064365ff7042f5a3eee09b06cc1";
    const ED25519_PUBLIC_KEY_SER_HEX: &str =
        "92a765643235353139c420587b8d516e9605a6ee57a19e2734f1ab3bb8b45e6062801dff3e6408d8594063";

    pub fn create_test_keypair() -> KeyPair {
        KeyPair::Ecdsa(ecdsa_secp384_test_keypair(0))
    }

    pub fn create_test_public_key() -> PublicKey {
        create_test_keypair().public_key()
    }

    #[test]
    fn ecdsa_public_key_serialize() {
        let public = PublicKey::Ecdsa(ecdsa_secp384_test_public_key(0));

        let buf = rmp_serialize(&public).unwrap();

        assert_eq!(hex::encode(&buf), ECDSA_PUBLIC_KEY_SER_HEX);
    }

    #[test]
    fn ecdsa_public_key_deserialize() {
        let buf = hex::decode(ECDSA_PUBLIC_KEY_SER_HEX).unwrap();

        let public = rmp_deserialize(&buf).unwrap();

        let expected = PublicKey::Ecdsa(ecdsa_secp384_test_public_key(0));
        assert_eq!(expected, public);
    }

    #[test]
    fn ed25519_public_key_serialize() {
        let public = PublicKey::Ed25519 {
            pb: ed25519_test_public_key(),
        };

        let buf = rmp_serialize(&public).unwrap();

        assert_eq!(hex::encode(&buf), ED25519_PUBLIC_KEY_SER_HEX);
    }

    #[test]
    fn ed25519_public_key_deserialize() {
        let buf = hex::decode(ED25519_PUBLIC_KEY_SER_HEX).unwrap();

        let public = rmp_deserialize(&buf).unwrap();

        let expected = PublicKey::Ed25519 {
            pb: ed25519_test_public_key(),
        };
        assert_eq!(expected, public);
    }
}
