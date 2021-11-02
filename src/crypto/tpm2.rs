use crate::crypto::ecdsa;
use crate::crypto::ecdsa::PublicKey;
use crate::{Error, ErrorKind, Result};

use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use tss_esapi::{
    attributes::SessionAttributesBuilder,
    constants::tss::{TPM2_ALG_NULL, TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    handles::KeyHandle,
    interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve},
    structures::{CreatePrimaryKeyResult, Digest},
    tcti_ldr::DeviceConfig,
    tss2_esys::{TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK},
    utils::{
        create_unrestricted_signing_ecc_public, AsymSchemeUnion, SignatureData::EcdsaSignature,
    },
    Context, Tcti,
};

use tss_esapi_sys::TPMS_ECC_POINT;

/// The TPM2 structure handles the device module, it let to sign digests and access the module pubic key.
/// context handles the interaction with the TPM2 module.
/// primary key holds the structure to sign with the primary private key.
/// public key is used to access the public key related to the primary private key
pub struct Tpm2 {
    context: Context,
    primary_key: KeyHandle,
    pub public_key: ecdsa::PublicKey,
}

#[allow(dead_code)]
impl Tpm2 {
    fn create_context(optional_device: Option<&str>) -> Result<Context> {
        let tpm_context_result;

        if let Some(device) = optional_device {
            tpm_context_result =
                Context::new(Tcti::Device(DeviceConfig::from_str(device).unwrap()));
        } else {
            tpm_context_result = Context::new(Tcti::Device(DeviceConfig::default()));
        }

        let result = tpm_context_result.is_err();
        if result {
            Err(Error::new_ext(ErrorKind::Tpm2Error, "unuable to find tpm"))
        } else {
            Ok(tpm_context_result.unwrap())
        }
    }

    fn set_session(context: &mut Context) -> Result<()> {
        let session = context.start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            tss_esapi::structures::SymmetricDefinition::Xor {
                hashing_algorithm: HashingAlgorithm::Sha256,
            },
            HashingAlgorithm::Sha256,
        );

        match session {
            Ok(session) => match session {
                Some(auth_session) => {
                    let (session_attributes, session_attributes_mask) =
                        SessionAttributesBuilder::new()
                            .with_decrypt(true)
                            .with_encrypt(true)
                            .build();
                    let result = context.tr_sess_set_attributes(
                        auth_session,
                        session_attributes,
                        session_attributes_mask,
                    );

                    match result {
                        Ok(_) => {
                            context.set_sessions((session, None, None));
                            Ok(())
                        }
                        Err(_) => Err(Error::new_ext(
                            ErrorKind::Tpm2Error,
                            "error during sessions attributes setup",
                        )),
                    }
                }
                None => Err(Error::new_ext(
                    ErrorKind::Tpm2Error,
                    "error during auth session generation",
                )),
            },
            Err(_) => Err(Error::new_ext(
                ErrorKind::Tpm2Error,
                "error during start authentication session",
            )),
        }
    }

    fn create_ecdsa_p256_primary_key_from_context(
        context: &mut Context,
    ) -> Result<CreatePrimaryKeyResult> {
        let ecc_structure = create_unrestricted_signing_ecc_public(
            AsymSchemeUnion::ECDSA(HashingAlgorithm::Sha256),
            EccCurve::NistP256,
        );

        match ecc_structure {
            Ok(ecc_structure) => {
                // for now `onwer` auth_value, may be changed lately
                let primary_handle = tss_esapi::interface_types::resource_handles::Hierarchy::Owner;
                let key_handle =
                    context.create_primary(primary_handle, &ecc_structure, None, None, None, None);

                match key_handle {
                    Ok(result) => Ok(result),
                    Err(_) => Err(Error::new_ext(
                        ErrorKind::Tpm2Error,
                        "something went wrong during key handle creation",
                    )),
                }
            }
            Err(_) => Err(Error::new_ext(
                ErrorKind::Tpm2Error,
                "something went wrong during TPM2B_public structure creation",
            )),
        }
    }

    fn retrieve_ecc_public_key(
        context: &mut Context,
        primary_key: &mut CreatePrimaryKeyResult,
    ) -> Result<TPMS_ECC_POINT> {
        let public_key = context.read_public(primary_key.key_handle);

        match public_key {
            Ok(public_key) => Ok(unsafe { public_key.0.publicArea.unique.ecc }),
            Err(_) => Err(Error::new_ext(
                ErrorKind::Tpm2Error,
                "something went wrong during key handle creation",
            )),
        }
    }

    /// It initialise the structure context, primary key and public key of the module passed as argument.
    /// optional device: path to a tpm2 device. Expected format: /dir0/dir1/[...]/tpm1.
    /// If no path is declared the default path is used: /dev/tpm0.
    /// It returns a Tpm2 structure or an error in case something went wrong during the interaction with the module.
    /// In case of success the Tpm2 structure has initialized with a public_key with a ecdsa::PublicKey structure.
    pub fn new(optional_device: Option<&str>) -> Result<Tpm2> {
        let mut context = Self::create_context(optional_device)?;

        Self::set_session(&mut context)?;
        let mut primary_key_result =
            Self::create_ecdsa_p256_primary_key_from_context(&mut context)?;
        let primary_key = Self::retrieve_ecc_public_key(&mut context, &mut primary_key_result)?;

        let mut public_key_value: Vec<u8> =
            primary_key.x.buffer[..primary_key.x.size as usize].to_vec();
        let mut public_key_value_y: Vec<u8> =
            primary_key.y.buffer[..primary_key.x.size as usize].to_vec();
        public_key_value.append(&mut public_key_value_y);

        let public_key = PublicKey {
            curve_id: ecdsa::CurveId::Secp256R1,
            value: public_key_value,
        };

        Ok(Tpm2 {
            context,
            primary_key: primary_key_result.key_handle,
            public_key,
        })
    }

    /// It sign the hashed data passed as argument in the method.
    /// hash: a buffer that contains the hashed digest to sign.
    /// it returns a Result that in case of success contains the sign in a buffer.
    /// Otherwise it contains an error that specify the problem in question.
    pub fn sign_data(&mut self, hash: &[u8]) -> Result<Vec<u8>> {
        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        let sign_result = self.context.sign(
            self.primary_key,
            &Digest::try_from(hash).unwrap(),
            scheme,
            validation.try_into().unwrap(),
        );

        match sign_result {
            Ok(sign_result) => {
                let mut sign_data = sign_result.signature;
                match &mut sign_data {
                    EcdsaSignature { r, s } => {
                        let mut sign_vector: Vec<u8> = Vec::with_capacity(r.len() + s.len());
                        sign_vector.append(r);
                        sign_vector.append(s);
                        Ok(sign_vector)
                    }
                    _ => Err(Error::new_ext(
                        ErrorKind::Tpm2Error,
                        "wrong sign elaboration",
                    )),
                }
            }
            Err(_) => Err(Error::new_ext(
                ErrorKind::Tpm2Error,
                "error while signing digest",
            )),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::ErrorKind;

    use super::Tpm2;
    #[test]
    fn test_tpm_init() {
        let tpm = Tpm2::new(None);
        match tpm {
            Ok(_tpm) => {
                assert!(true);
            }
            Err(error) => {
                assert_eq!(error.kind, ErrorKind::Tpm2Error);
                assert_eq!(error.to_string(), "tpm interaction error");
            }
        }
    }

    #[test]
    fn test_key_creation() {
        let tpm = Tpm2::new(None);

        match tpm {
            Ok(tpm) => {
                println!("public key:   {}", hex::encode(&tpm.public_key.value));
                assert!(!tpm.public_key.value.is_empty())
            }
            Err(error) => {
                assert_eq!(error.kind, ErrorKind::Tpm2Error);
                assert_eq!(error.to_string(), "tpm interaction error");
            }
        }
    }

    use ring::digest;

    #[test]
    fn test_sign() {
        let tpm = Tpm2::new(None);
        match tpm {
            Ok(mut tpm) => {
                let hash = digest::digest(&digest::SHA256, b"hello world");
                println!("digest:   {}", hex::encode(hash.as_ref()));

                let sign = tpm.sign_data(hash.as_ref());

                match sign {
                    Ok(sign) => {
                        println!("sign:   {}", hex::encode(&sign));
                        assert!(!sign.is_empty())
                    }
                    Err(error) => {
                        assert_eq!(error.kind, ErrorKind::Tpm2Error);
                        assert_eq!(error.to_string(), "tpm interaction error");
                    }
                }
            }
            Err(error) => {
                assert_eq!(error.kind, ErrorKind::Tpm2Error);
                assert_eq!(error.to_string(), "tpm interaction error");
            }
        }
    }
}
