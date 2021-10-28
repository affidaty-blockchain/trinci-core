use crate::crypto::ecdsa::PublicKey;
use crate::crypto::ecdsa;
use crate::{Error, ErrorKind, Result};

use std::convert::TryFrom;
use std::str::FromStr;
use std::convert::TryInto;

use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::tss::{TPM2_ALG_NULL, TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve};
use tss_esapi::structures::{CreatePrimaryKeyResult, Digest};
use tss_esapi::tcti_ldr::DeviceConfig;
use tss_esapi::tss2_esys::{TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK};
use tss_esapi::utils::{create_unrestricted_signing_ecc_public, AsymSchemeUnion};
use tss_esapi::{Context, Tcti};
use tss_esapi::utils::SignatureData::EcdsaSignature;
use tss_esapi_sys::TPMS_ECC_POINT;

pub struct Tpm2 {
    context: Context,
    primary_key: KeyHandle,
    pub public_key: ecdsa::PublicKey,
}

impl Tpm2 {
    fn create_context(optional_device: Option<&str>) -> Result<Context> {
        let tpm_context_result;
        
        if let Some(device) = optional_device {
            tpm_context_result = Context::new(Tcti::Device(DeviceConfig::from_str(device).unwrap()));
        } else {
            tpm_context_result = Context::new(Tcti::Device(DeviceConfig::default()));
        }

        let result = tpm_context_result.is_err();
        if result {
            Err(Error::new_ext(ErrorKind::Other, "unable to find tpm module"))
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
            Ok(session) => {
                let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build();
                let result = context.tr_sess_set_attributes(
                    session.unwrap(),
                    session_attributes,
                    session_attributes_mask,
                );
    
                match result {
                    Ok(_) => Ok(context.set_sessions((session, None, None))),
                    Err(_) =>  Err(Error::new_ext(ErrorKind::Other, "error during sessions attributes setup")),
                }
            }
            Err(_) =>  Err(Error::new_ext(ErrorKind::Other, "error during start authentication session")),
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
                    Err(_) =>  Err(Error::new_ext(ErrorKind::Other, "something went wrong during key handle creation")),
                }
            }
            Err(_) =>  Err(Error::new_ext(ErrorKind::Other, "something went wrong during TPM2B_public structure creation")),
        }
    }
    
    fn retrieve_ecc_public_key(
        context: &mut Context,
        primary_key: &mut CreatePrimaryKeyResult
    ) -> Result<TPMS_ECC_POINT> {
        let public_key = context.read_public(primary_key.key_handle);
    
        match public_key {
            Ok(public_key) => Ok(unsafe { public_key.0.publicArea.unique.ecc }),
            Err(_) =>  Err(Error::new_ext(ErrorKind::Other, "something went wrong during key handle creation")),
        }
    }

    pub fn new(optional_device: Option<&str>) -> Result<Tpm2> {
        let mut context = Self::create_context(optional_device);
        match context {
            Ok(mut context) => {
                let is_established = Self::set_session(&mut context);
                match is_established {
                    Ok(_) => {
                        let primary_key_result = Self::create_ecdsa_p256_primary_key_from_context(&mut context);
                        match primary_key_result {
                            Ok(mut primary_key_result) => {
                                let primary_key = Self::retrieve_ecc_public_key(&mut context, &mut primary_key_result);
                                match primary_key {
                                    Ok(primary_key) => {
                                        let mut public_key_value: Vec<u8> = primary_key.x.buffer[..primary_key.x.size as usize].iter().cloned().collect(); 
                                        let mut public_key_value_y: Vec<u8> = primary_key.y.buffer[..primary_key.x.size as usize].iter().cloned().collect(); 
                                        public_key_value.append(&mut public_key_value_y);

                                        let public_key = PublicKey {
                                            curve_id: ecdsa::CurveId::Secp256R1,
                                            value: public_key_value, 
                                        }; 
                                        
                                        Ok(Tpm2 {
                                            context,
                                            primary_key: primary_key_result.key_handle.clone(),
                                            public_key , 
                                        })
                                    },
                                    Err(error) => Err(Error::new_ext(ErrorKind::Other, error)),
                                } 
                            },
                            Err(error) => Err(Error::new_ext(ErrorKind::Other, error)),
                        }
                    },
                    Err(error) => Err(Error::new_ext(ErrorKind::Other, error)),

                }
            },
            Err(error) => Err(Error::new_ext(ErrorKind::Other, error)),
        }

    }

    fn sign_data(&mut self, hash: &[u8]) -> Result<Vec<u8>> {
    
        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        
        
        let sign_result = self.context
            .sign(
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
                    },
                    _ =>  Err(Error::new_ext(ErrorKind::Other, "wrong sign elaboration")),
                }
            },
            Err(_) => Err(Error::new_ext(ErrorKind::Other, "errore while signing digest")),
        }
                                
    }
}

#[cfg(test)]
mod tests {
    use super::Tpm2;
 
    #[test]
    fn test_key_creation() {
        let tpm = Tpm2::new(None);
        
        match tpm {
            Ok(tpm) => {
                todo!()
            }
            Err(_) => println!("error during tpm creation"),
        }
    }
}