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

//! Opaque cryptographic secure hash used by the overall project.
//!
//! Current implementation uses SHA-256.
//!
//! The serialization uses [Multihash](https://multiformats.io/multihash) format
//! to keep a door opened for future extensions.
//!
//! Complete multihash table lives
//! [here](https://github.com/multiformats/multicodec/blob/master/table.csv).

use crate::{base::serialize, Error, ErrorKind, Result};
use ring::digest;
use serde::{de::Visitor, Deserializer, Serializer};

/// Available hash algorithms.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
#[derive(Default)]
pub enum HashAlgorithm {
    #[default]
    Identity,
    Sha256,
}



/// Current default algorithm used by the library internals.
pub const PRIMARY_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

/// Multihash tag for Identity
const MULTIHASH_TYPE_IDENTITY: u8 = 0x00;
/// Multihash SHA-256 type
const MULTIHASH_TYPE_SHA256: u8 = 0x12;

/// Max length of multihash value.
const MULTIHASH_VALUE_LEN_MAX: usize = 36;

/// Max serialized length.
const MULTIHASH_BYTES_LEN_MAX: usize = 2 + MULTIHASH_VALUE_LEN_MAX;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Hash([u8; MULTIHASH_BYTES_LEN_MAX]);

impl Default for Hash {
    fn default() -> Self {
        // Implicitly sets algorithm to "identity" and length to 0
        Hash([0; MULTIHASH_BYTES_LEN_MAX])
    }
}

impl Hash {
    // Creates a new instance by wrapping precomputed hash bytes.
    pub fn new(alg: HashAlgorithm, bytes: &[u8]) -> Result<Self> {
        let mut hash = Hash::default();
        let hash_len = bytes.len();
        if hash_len > MULTIHASH_VALUE_LEN_MAX {
            return Err(Error::new(ErrorKind::MalformedData));
        }
        let hash_alg = match alg {
            HashAlgorithm::Identity => MULTIHASH_TYPE_IDENTITY,
            HashAlgorithm::Sha256 => {
                if hash_len > 32 {
                    return Err(Error::new(ErrorKind::MalformedData));
                }
                MULTIHASH_TYPE_SHA256
            }
        };
        hash.0[0] = hash_alg;
        hash.0[1] = hash_len as u8;
        hash.0[2..(2 + hash_len)].copy_from_slice(bytes);
        Ok(hash)
    }

    /// Construct from bytes slice from a bytes slice representing the
    /// serialized multihash of one of the supported hash algorithms.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes_len = bytes.len();
        if bytes_len < 2 {
            return Err(Error::new(ErrorKind::MalformedData));
        }
        let hash_len = bytes[1] as usize;
        if hash_len != bytes_len - 2 {
            return Err(Error::new(ErrorKind::MalformedData));
        }
        let alg = match bytes[0] {
            MULTIHASH_TYPE_IDENTITY => HashAlgorithm::Identity,
            MULTIHASH_TYPE_SHA256 => HashAlgorithm::Sha256,
            _ => return Err(Error::new(ErrorKind::MalformedData)),
        };
        Hash::new(alg, &bytes[2..])
    }

    /// Returns the hash serialized as a multihash.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..self.size()]
    }

    /// Returns the hash serialized as a multihash.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Compute hash from arbitrary data.
    pub fn from_data(alg: HashAlgorithm, data: &[u8]) -> Self {
        match alg {
            HashAlgorithm::Sha256 => {
                let digest = digest::digest(&digest::SHA256, data);
                Hash::new(alg, digest.as_ref()).unwrap()
            }
            HashAlgorithm::Identity => {
                Hash::new(alg, data).unwrap() // FIXME: this panics if data.len() > max
            }
        }
    }

    /// Creates a new instance from a hex string.
    /// Mostly used for testing.
    pub fn from_hex(hex: &str) -> Result<Self> {
        match hex::decode(hex) {
            Ok(buf) => Self::from_bytes(&buf),
            Err(_) => Err(Error::new(ErrorKind::MalformedData)),
        }
    }

    /// Multihash bytes size.
    /// Computed as: algorithm type (1 byte) + wrapped value length (1 byte) + wrapped value bytes.
    pub fn size(&self) -> usize {
        2 + self.hash_size()
    }

    /// Wrapped hash size.
    pub fn hash_size(&self) -> usize {
        self.0[1] as usize
    }

    /// Wrapped hash type.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self.0[0] {
            MULTIHASH_TYPE_IDENTITY => HashAlgorithm::Identity,
            MULTIHASH_TYPE_SHA256 => HashAlgorithm::Sha256,
            _ => panic!("Unexpected multihash type"),
        }
    }

    /// Wrapped hash bytes.
    pub fn hash_value(&self) -> &[u8] {
        &self.0[2..]
    }
}

/// Get a reference to the inner bytes array.
impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl serde::Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashVisitor;

        impl<'v> Visitor<'v> for HashVisitor {
            type Value = Hash;

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
                Hash::from_bytes(bytes)
                    .map_err(|_err| serde::de::Error::custom("Invalid multihash"))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }
        }
        deserializer.deserialize_byte_buf(HashVisitor)
    }
}

/// A trait for types that can be hashed.
pub trait Hashable {
    /// Hash using the chosen hash algorithm.
    fn hash(&self, alg: HashAlgorithm) -> Hash;

    /// Hash using the library main algorithm.
    fn primary_hash(&self) -> Hash {
        self.hash(PRIMARY_HASH_ALGORITHM)
    }
}

/// Blanket implementation for all types that can be serialized using
/// MessagePack.
impl<T: serde::Serialize> Hashable for T {
    fn hash(&self, alg: HashAlgorithm) -> Hash {
        let buf = serialize::rmp_serialize(self).unwrap();
        Hash::from_data(alg, &buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::base::serialize::{rmp_deserialize, rmp_serialize};

    use super::*;

    const HASH_HEX: &str =
        "c4221220879ecb0adedfa6a8aa19d972d225c3ce74d95619fda302ab4090fcff2ab45e6f";

    #[test]
    fn hash_serialize() {
        let hash = Hash::from_hex(&HASH_HEX[4..]).unwrap();

        let buf = rmp_serialize(&hash).unwrap();

        assert_eq!(hex::encode(&buf), HASH_HEX);
    }

    #[test]
    fn hash_deserialize() {
        let expected = Hash::from_hex(&HASH_HEX[4..]).unwrap();
        let buf = hex::decode(HASH_HEX).unwrap();

        let hash: Hash = rmp_deserialize(&buf).unwrap();

        assert_eq!(hash, expected);
    }
}
