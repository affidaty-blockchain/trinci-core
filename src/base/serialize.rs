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

use crate::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};

/// Serialize using MessagePack format (without field names).
///
/// # Error
///
/// If the data cannot be serialized a `MalformedData` error kind is returned.
pub fn rmp_serialize<T>(val: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    rmp_serde::to_vec(val).map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))
}

/// Deserialize using MessagePack format.
///
/// # Error
///
/// If the data cannot be deserialized a `MalformedData` error kind is returned.
pub fn rmp_deserialize<'a, T>(buf: &'a [u8]) -> Result<T>
where
    T: Deserialize<'a>,
{
    rmp_serde::from_slice(buf).map_err(|err| Error::new_ext(ErrorKind::MalformedData, err))
}

/// Trait implemented by all types that can be serialized with MessagePack format.
pub trait MessagePack<'a>: Sized + Serialize + Deserialize<'a> {
    /// Serialize using MessagePack format.
    ///
    /// # Panics
    ///
    /// Panics if the concrete type cannot be serialized using message pack.
    fn serialize(&self) -> Vec<u8> {
        rmp_serialize(self).unwrap() // Safe for core structs.
    }

    /// Deserialize using MessagePack format.
    ///
    /// # Errors
    ///
    /// Propagates the message pack decoder error.
    fn deserialize(buf: &'a [u8]) -> Result<Self> {
        rmp_deserialize(buf)
    }
}

/// Blanket implementation for types implementing `Serialize` and `Deserialize`.
impl<'a, T: Serialize + Deserialize<'a>> MessagePack<'a> for T {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
    struct SubStruct<'a> {
        field1: u32,
        field2: &'a str,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
    struct MyStruct<'a> {
        name: &'a str,
        surname: String,
        #[serde(with = "serde_bytes")]
        a_buf: &'a [u8],
        a_vec8: Vec<u8>,
        a_vec16: Vec<u16>,
        a_map: BTreeMap<&'a str, SubStruct<'a>>,
    }

    impl<'a> MyStruct<'a> {
        fn new() -> Self {
            let mut map = BTreeMap::new();
            map.insert(
                "k1",
                SubStruct {
                    field1: 123,
                    field2: "foo",
                },
            );
            map.insert(
                "k2",
                SubStruct {
                    field1: 456,
                    field2: "bar",
                },
            );
            map.insert(
                "k3",
                SubStruct {
                    field1: 789,
                    field2: "baz",
                },
            );
            Self {
                name: "Davide",
                surname: "Galassi".to_string(),
                a_buf: &[0x01, 0xFF, 0x80],
                a_vec8: vec![0x01, 0xFF, 0x80],
                a_vec16: vec![0x01, 0xFF, 0x80],
                a_map: map,
            }
        }
    }

    const MYSTRUCT_HEX: &str = "96a6446176696465a747616c61737369c40301ff809301ccffcc809301ccffcc8083a26b31927ba3666f6fa26b3292cd01c8a3626172a26b3392cd0315a362617a";

    #[test]
    fn mystruct_serialize() {
        let st = MyStruct::new();

        let buf = rmp_serialize(&st).unwrap();

        assert_eq!(hex::encode(&buf), MYSTRUCT_HEX);
    }

    #[test]
    fn mystruct_deserialize() {
        let exp = MyStruct::new();
        let buf = hex::decode(MYSTRUCT_HEX).unwrap();

        let st: MyStruct = rmp_deserialize(&buf).unwrap();

        assert_eq!(st, exp);
    }
}
