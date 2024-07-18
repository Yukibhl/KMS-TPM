use std::str::FromStr;
use tss_esapi::{Context, TctiNameConf};
use tss_esapi::attributes::{ObjectAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{HashScheme, KeyedHashScheme, Public, PublicBuilder, PublicKeyedHashParameters, PublicRsaParametersBuilder,RsaScheme, SensitiveData, SymmetricDefinition};
use tss_esapi::tcti_ldr::{DeviceConfig};

fn main() {
    // Create a new context for TPM interaction
    let mut context = Context::new(TctiNameConf::Device(DeviceConfig::from_str("/dev/tpm0").unwrap()))
        .expect("Failed to get TCTI");

    // Create RSA parameters
    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_key_bits(RsaKeyBits::Rsa1024)
        .build()
        .expect("Failed to build RSA parameters");

    // Create object attributes
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_decrypt(true)
        .with_sign_encrypt(false) // Adjust based on your requirements
        .with_user_with_auth(false)
        .with_sensitive_data_origin(true)
        .build()
        .expect("Failed to build object attributes");

    // Create public key object
    let public = Public::Rsa {
        object_attributes,
        name_hashing_algorithm: HashingAlgorithm::Sha1,
        auth_policy: Default::default(),
        parameters: rsa_params,
        unique: Default::default(),
    };

    // Start an HMAC session
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to start session");

    context.set_sessions((session, None, None));

    // Create primary key handle
    let key_handle = context
        .create_primary(
            Hierarchy::Owner,
            public,
            None,
            None,
            None,
            None,
        )
        .expect("Failed to create key handle");

    // Data to be sealed
    let data_to_seal = SensitiveData::try_from("secret data".as_bytes().to_vec())
        .expect("Failed to create SensitiveData from the data to be sealed");

    // Create public structure for the sealed data
    let seal_public = PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .expect("Failed to build Public structure for sealing");

    // Seal the data
    let sealed_object = context
        .create(
            key_handle.key_handle,
            seal_public,
            None,
            Some(data_to_seal),
            None,
            None,
        )
        .expect("Failed to seal data");
    println!("Sealed data: {:?}", sealed_object.out_private);

    let loaded_key = context
        .load(key_handle.key_handle, sealed_object.out_private, sealed_object.out_public)
        .expect("Failed to load sealed object");

    // Unseal the data
    let unsealed_data = context
        .unseal(ObjectHandle::from(loaded_key))
        .expect("Failed to unseal data");

    println!("Unsealed data: {:?}", unsealed_data.value());

    // Clean up
    context
        .flush_context(ObjectHandle::from(key_handle.key_handle))
        .expect("Failed to flush key handle context");
    context
        .flush_context(ObjectHandle::from(SessionHandle::from(session)))
        .expect("Failed to flush session context");



}
