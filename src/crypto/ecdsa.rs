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

#[cfg(feature = "tpm2")]
use crate::tpm2::Tpm2;
use crate::{
    crypto::{Hash, HashAlgorithm},
    Error, ErrorKind, Result,
};
use ring::{
    rand::SystemRandom,
    signature::{
        self, EcdsaKeyPair as EcdsaKeyPairImpl, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm,
        KeyPair as RingKeyPair, UnparsedPublicKey as RingPublicKey,
    },
};
use serde::{Deserialize, Serialize};

crate::named_unit_variant!(secp256r1);
crate::named_unit_variant!(secp384r1);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(untagged)]
pub enum CurveId {
    #[serde(with = "secp256r1")]
    Secp256R1,
    #[serde(with = "secp384r1")]
    Secp384R1,
}

#[derive(Debug)]
enum TrinciEcdsaKeyPairImpl {
    Ring(EcdsaKeyPairImpl),
    #[cfg(feature = "tpm2")]
    Tpm2(Tpm2),
}

#[derive(Debug)]
pub struct KeyPair {
    curve_id: CurveId,
    imp: TrinciEcdsaKeyPairImpl,
    rng: SystemRandom,
}

impl KeyPair {
    /// Instantiante new keypair given its private and public components.
    pub fn new(curve_id: CurveId, private_bytes: &[u8], public_bytes: &[u8]) -> Result<KeyPair> {
        let alg = Self::get_alg(curve_id);
        let imp =
            EcdsaKeyPairImpl::from_private_key_and_public_key(alg, private_bytes, public_bytes)
                .map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))?;
        Ok(KeyPair {
            curve_id,
            imp: TrinciEcdsaKeyPairImpl::Ring(imp),
            rng: SystemRandom::new(),
        })
    }

    #[cfg(feature = "tpm2")]
    pub fn new_tpm2(curve_id: CurveId, device: &str) -> Result<KeyPair> {
        let imp = Tpm2::new(Some(device))?;
        Ok(KeyPair {
            curve_id,
            imp: TrinciEcdsaKeyPairImpl::Tpm2(imp),
            rng: SystemRandom::new(),
        })
    }

    /// Load keypair from pkcs#8 byte array.
    pub fn from_pkcs8_bytes(curve_id: CurveId, bytes: &[u8]) -> Result<KeyPair> {
        let alg = Self::get_alg(curve_id);
        let imp = EcdsaKeyPairImpl::from_pkcs8(alg, bytes)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;
        Ok(KeyPair {
            curve_id,
            imp: TrinciEcdsaKeyPairImpl::Ring(imp),
            rng: SystemRandom::new(),
        })
    }

    /// Digital signature.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.imp {
            TrinciEcdsaKeyPairImpl::Ring(imp) => {
                let sig = imp
                    .sign(&self.rng, data)
                    .map_err(|err| Error::new_ext(ErrorKind::Other, err))?
                    .as_ref()
                    .to_vec();
                Ok(sig)
            }
            #[cfg(feature = "tpm2")]
            TrinciEcdsaKeyPairImpl::Tpm2(imp) => {
                let sig = imp.sign_data(data)?;
                Ok(sig.to_vec())
            }
        }
    }

    /// Get public key from keypair.
    pub fn public_key(&self) -> PublicKey {
        match &self.imp {
            TrinciEcdsaKeyPairImpl::Ring(imp) => {
                let public = imp.public_key().as_ref().to_vec();
                PublicKey {
                    curve_id: self.curve_id,
                    value: public,
                }
            }
            #[cfg(feature = "tpm2")]
            TrinciEcdsaKeyPairImpl::Tpm2(imp) => imp.public_key.clone(),
        }
    }

    fn get_alg(curve_id: CurveId) -> &'static EcdsaSigningAlgorithm {
        match curve_id {
            CurveId::Secp256R1 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            CurveId::Secp384R1 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PublicKey {
    pub curve_id: CurveId,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl PublicKey {
    /// Signature verification procedure.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        let alg = Self::get_alg(self.curve_id);
        let imp = RingPublicKey::new(alg, &self.value);
        imp.verify(data, sig).is_ok()
    }

    /// Public key to account id.
    /// The implementation is compatible with libp2p PeerId generation.
    pub fn to_account_id(&self) -> String {
        let bytes = self.value.to_owned();
        let bytes = add_asn1_x509_header(self.curve_id, bytes);
        let bytes = add_protobuf_header(bytes);
        let hash = Hash::from_data(HashAlgorithm::Sha256, &bytes);
        bs58::encode(hash).into_string()
    }

    fn get_alg(curve_id: CurveId) -> &'static EcdsaVerificationAlgorithm {
        match curve_id {
            CurveId::Secp256R1 => &signature::ECDSA_P256_SHA256_FIXED,
            CurveId::Secp384R1 => &signature::ECDSA_P384_SHA384_FIXED,
        }
    }
}

// SECG named elliptic curve)
fn get_curve_oid(curve_id: CurveId) -> Vec<u8> {
    match curve_id {
        // secp256v1 OID: 1.2.840.10045.3.1.7
        CurveId::Secp256R1 => vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // secp384r1 OID: 1.3.132.0.34
        CurveId::Secp384R1 => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
    }
}

// ASN1 header.
#[rustfmt::skip]
fn add_asn1_x509_header(curve_id: CurveId, mut key_bytes: Vec<u8>) -> Vec<u8> {
    let mut res = vec![
        // ASN.1 struct type and length.
        0x30, 0x00,
        // ASN.1 struct type and length.
        0x30, 0x00,
    ];

    // OIDS: 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    let mut ec_oid = vec![ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 ];
    let mut curve_oid = get_curve_oid(curve_id);
    let oids_len = ec_oid.len() + curve_oid.len();
    res.append(&mut ec_oid);
    res.append(&mut curve_oid);

    // Update oids length field
    res[3] = oids_len as u8;

    // Append key bitstring type and length.
    let mut bitstring_type_len = vec![
        0x03, (key_bytes.len() + 1) as u8, 0x00,
    ];
    res.append(&mut bitstring_type_len);
    // Append key bitstring.
    res.append(&mut key_bytes);
    // Update overall length field.
    res[1] = (res.len() - 2) as u8;

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
        KeyPair::new(CurveId::Secp384R1, &private_bytes, &public_bytes).unwrap()
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

    #[cfg(feature = "tpm2")]
    #[test]
    fn sign_data_tpm() {
        if let Ok(keypair) = KeyPair::new_tpm2(CurveId::Secp256R1, "/dev/tpm0") {
            let data = "hello world";

            let sign = keypair.sign(data.as_bytes()).unwrap();
            println!("\nsign:   {}", hex::encode(&sign));
            println!("---");
            assert!(keypair.public_key().verify(data.as_bytes(), &sign));
        }
    }
}
