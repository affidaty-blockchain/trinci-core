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

//! Library error codes and results.

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Display, Formatter};

/// Project-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Max string length when the error is converted to string using `to_string_full`.
const MAX_ERROR_SOURCE_STRING_LENGTH: usize = 128;

/// Error kind to better contextualize the returned error.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ErrorKind {
    MalformedData,
    BadNetwork,
    InvalidSignature,
    DuplicatedUnconfirmedTx,
    DuplicatedConfirmedTx,
    DatabaseFault,
    WasmMachineFault,
    SmartContractFault,
    ResourceNotFound,
    NotImplemented,
    Other,
}

/// Error kind strings.
pub(super) mod error_kind_str {
    pub const MALFORMED_DATA: &str = "malformed data";
    pub const BAD_NETWORK: &str = "bad network";
    pub const INVALID_SIGNATURE: &str = "invalid signature";
    pub const DUPLICATED_UNCONFIRMED_TX: &str = "duplicated unconfirmed transaction";
    pub const DUPLICATED_CONFIRMED_TX: &str = "duplicated confirmed transaction";
    pub const RESOURCE_NOT_FOUND: &str = "resource not found";
    pub const DATABASE_FAULT: &str = "database fault";
    pub const WASM_MACHINE_FAULT: &str = "wasm machine fault";
    pub const SMART_CONTRACT_FAULT: &str = "smart contract fault";
    pub const NOT_IMPLEMENTED: &str = "not implemented";
    pub const OTHER: &str = "other";
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use ErrorKind::*;
        let kind_str = match self {
            MalformedData => error_kind_str::MALFORMED_DATA,
            BadNetwork => error_kind_str::BAD_NETWORK,
            InvalidSignature => error_kind_str::INVALID_SIGNATURE,
            DuplicatedUnconfirmedTx => error_kind_str::DUPLICATED_UNCONFIRMED_TX,
            DuplicatedConfirmedTx => error_kind_str::DUPLICATED_CONFIRMED_TX,
            ResourceNotFound => error_kind_str::RESOURCE_NOT_FOUND,
            DatabaseFault => error_kind_str::DATABASE_FAULT,
            WasmMachineFault => error_kind_str::WASM_MACHINE_FAULT,
            SmartContractFault => error_kind_str::SMART_CONTRACT_FAULT,
            NotImplemented => error_kind_str::NOT_IMPLEMENTED,
            Other => error_kind_str::OTHER,
        };
        write!(f, "{}", kind_str)
    }
}

impl Serialize for ErrorKind {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let msg = self.to_string();
        serializer.serialize_str(&msg)
    }
}

impl<'de> Deserialize<'de> for ErrorKind {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorKindVisitor;

        impl<'de> Visitor<'de> for ErrorKindVisitor {
            type Value = String;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<R>(self, value: &str) -> std::result::Result<String, R> {
                Ok(value.to_string())
            }
        }

        let kind = match deserializer.deserialize_str(ErrorKindVisitor)?.as_str() {
            error_kind_str::MALFORMED_DATA => ErrorKind::MalformedData,
            error_kind_str::BAD_NETWORK => ErrorKind::BadNetwork,
            error_kind_str::INVALID_SIGNATURE => ErrorKind::InvalidSignature,
            error_kind_str::DUPLICATED_UNCONFIRMED_TX => ErrorKind::DuplicatedUnconfirmedTx,
            error_kind_str::DUPLICATED_CONFIRMED_TX => ErrorKind::DuplicatedConfirmedTx,
            error_kind_str::RESOURCE_NOT_FOUND => ErrorKind::ResourceNotFound,
            error_kind_str::DATABASE_FAULT => ErrorKind::DatabaseFault,
            error_kind_str::WASM_MACHINE_FAULT => ErrorKind::WasmMachineFault,
            error_kind_str::SMART_CONTRACT_FAULT => ErrorKind::SmartContractFault,
            error_kind_str::NOT_IMPLEMENTED => ErrorKind::NotImplemented,
            _ => ErrorKind::Other,
        };
        Ok(kind)
    }
}

/// Project-wide error type.
/// Contains a kind enumerate and a `source` to identify the subsystem that may
/// have propageted the error.
#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    /// Error kind.
    pub kind: ErrorKind,
    /// Not propagated by blockchain messages.
    #[serde(serialize_with = "source_se", deserialize_with = "source_de")]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

fn source_se<S: Serializer>(
    source: &Option<Box<dyn std::error::Error + Send + Sync>>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match source {
        Some(b) => s.serialize_str(&b.to_string()),
        None => s.serialize_unit(),
    }
}

fn source_de<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Box<dyn std::error::Error + Send + Sync>>, D::Error> {
    struct ErrorVisitor;

    impl<'de> Visitor<'de> for ErrorVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<R>(self, value: &str) -> std::result::Result<String, R> {
            Ok(value.to_string())
        }
    }

    match d.deserialize_str(ErrorVisitor) {
        Ok(s) => Ok(Some(s.into())),
        Err(_err) => Ok(None),
    }
}

impl Clone for Error {
    fn clone(&self) -> Self {
        Error {
            kind: self.kind,
            source: None,
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error::new(kind)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::new_ext(ErrorKind::Other, s)
    }
}

impl<T> From<ErrorKind> for Result<T> {
    fn from(kind: ErrorKind) -> Self {
        Err(kind.into())
    }
}

impl Error {
    pub fn new_ext<E>(kind: ErrorKind, error: E) -> Error
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let source = error.into();
        Error {
            kind,
            source: Some(source),
        }
    }

    pub fn new(kind: ErrorKind) -> Error {
        Error { kind, source: None }
    }

    pub fn to_string_full(&self) -> String {
        let mut err_string = self.to_string();
        if let Some(ref source) = self.source {
            let detail = format!(": {}", source.to_string());
            let max_len = std::cmp::min(detail.len(), MAX_ERROR_SOURCE_STRING_LENGTH);
            err_string.push_str(&detail[..max_len]);
        }
        err_string
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        if self.kind != other.kind {
            return false;
        }
        if self.source.is_none() && other.source.is_none() {
            true
        } else if self.source.is_some() && other.source.is_some() {
            format!("{:?}", self.source) == format!("{:?}", other.source)
        } else {
            false
        }
    }
}

impl std::error::Error for Error {
    #[allow(clippy::all)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Code suggested by clippy doesn't compile... further investigation required
        // self.source.as_ref().map(|source| source.as_ref())
        match self.source {
            None => None,
            Some(ref source) => Some(source.as_ref()),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &format!("{}", self.kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::serialize::{rmp_deserialize, rmp_serialize};
    use std::io;
    use ErrorKind::*;

    #[test]
    fn generic_error_type() {
        let src1 = io::Error::new(io::ErrorKind::PermissionDenied, "oh no!");
        let src2 = io::Error::new(io::ErrorKind::TimedOut, "oh no!");
        let err1 = Error::new_ext(DatabaseFault, src1);
        let err2 = Error::new_ext(DatabaseFault, src2);

        assert_ne!(err1, err2);
    }

    #[test]
    fn external_db_failure() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "oh no!");

        let error = Error::new_ext(DatabaseFault, source);

        assert_eq!(error.to_string(), "database fault");
        assert_eq!(error.to_string_full(), "database fault: oh no!");
        let source = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
        assert!(std::error::Error::source(&source).is_none());
    }

    const ERROR_HEX: &str = "92ae6461746162617365206661756c74a66f68206e6f21";
    const ERROR_NO_SOURCE_HEX: &str = "92ae6461746162617365206661756c74c0";

    #[test]
    fn error_serialize() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "oh no!");
        let error = Error::new_ext(DatabaseFault, source);

        let buf = rmp_serialize(&error).unwrap();

        assert_eq!(hex::encode(&buf), ERROR_HEX);
    }

    #[test]
    fn error_deserialize() {
        let buf = hex::decode(ERROR_HEX).unwrap();

        let err: Error = rmp_deserialize(&buf).unwrap();

        assert_eq!(err, Error::new_ext(DatabaseFault, "oh no!"));
    }

    #[test]
    fn error_serialize_no_source() {
        let error = Error::new(DatabaseFault);

        let buf = rmp_serialize(&error).unwrap();

        assert_eq!(hex::encode(&buf), ERROR_NO_SOURCE_HEX);
    }

    #[test]
    fn error_deserialize_no_source() {
        let buf = hex::decode(ERROR_NO_SOURCE_HEX).unwrap();

        let err: Error = rmp_deserialize(&buf).unwrap();

        assert_eq!(err, Error::new(DatabaseFault));
    }
}
