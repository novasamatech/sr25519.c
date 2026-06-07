// for enum variants
#![allow(unused_variables)]
#![allow(non_snake_case)]

extern crate schnorrkel;
extern crate merlin;

// Copyright 2025 ERussel via https://github.com/novasamatech/sr25519.c
// Copyright 2021 ERussel via https://github.com/ERussel/sr25519-crust/tree/feature/ios-support
// Copyright 2019 Soramitsu via https://github.com/Warchant/sr25519-crust
// Copyright 2019 Paritytech via https://github.com/paritytech/schnorrkel-js/
// Copyright 2019 @polkadot/wasm-schnorrkel authors & contributors
// This software may be modified and distributed under the terms
// of the Apache-2.0 license. See the LICENSE file for details.

// Originally developed (as a fork) in https://github.com/polkadot-js/schnorrkel-js/
// which was adopted from the initial https://github.com/paritytech/schnorrkel-js/
// forked at commit eff430ddc3090f56317c80654208b8298ef7ab3f

use std::os::raw::c_ulong;
use std::ptr;
use std::slice;

use merlin::Transcript;
use schnorrkel::{
    context::signing_context,
    derive::{CHAIN_CODE_LENGTH, ChainCode, Derivation}, ExpansionMode, Keypair, MiniSecretKey, PublicKey,
    SecretKey, Signature, SignatureError, vrf::{VRFOutput, VRFProof}};
use std::fmt::{Formatter, Error};

// cbindgen has an issue with macros, so define it outside,
// otherwise it would've been possible to avoid duplication of macro variant list
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Sr25519Result {
    Ok,
    EquationFalse,
    PointDecompressionError,
    ScalarFormatError,
    BytesLengthError,
    NotMarkedSchnorrkel,
    MuSigAbsent,
    MuSigInconsistent,
}

/// converts from schnorrkel::SignatureError
/// to Sr25519Result (which is exported to C header)
fn convert_error(err: &SignatureError) -> Sr25519Result {
    match err {
        SignatureError::EquationFalse => Sr25519Result::EquationFalse,
        SignatureError::PointDecompressionError => Sr25519Result::PointDecompressionError,
        SignatureError::ScalarFormatError => Sr25519Result::ScalarFormatError,
        SignatureError::BytesLengthError { name: _, description: _, length: _ }
        => Sr25519Result::BytesLengthError,
        SignatureError::MuSigAbsent { musig_stage: _ } => Sr25519Result::MuSigAbsent,
        SignatureError::MuSigInconsistent { musig_stage: _, duplicate: _ }
        => Sr25519Result::MuSigInconsistent,
        SignatureError::NotMarkedSchnorrkel => Sr25519Result::NotMarkedSchnorrkel
    }
}

// We must make sure that this is the same as declared in the substrate source code.
const SIGNING_CTX: &'static [u8] = b"substrate";
pub const BABE_VRF_PREFIX: &'static [u8] = b"substrate-babe-vrf";


/// ChainCode construction helper
fn create_cc(data: &[u8]) -> ChainCode {
    let mut cc = [0u8; CHAIN_CODE_LENGTH];

    cc.copy_from_slice(&data);

    ChainCode(cc)
}

/// Keypair helper function.
fn create_from_seed(seed: &[u8]) -> Result<Keypair, SignatureError> {
    MiniSecretKey::from_bytes(seed).map(|mini| mini.expand_to_keypair(ExpansionMode::Ed25519))
}

/// Keypair helper function.
fn create_from_pair(pair: &[u8]) -> Result<Keypair, SignatureError> {
    Keypair::from_bytes(pair)
}

/// PublicKey helper
fn create_public(public: &[u8]) -> Result<PublicKey, SignatureError> {
    PublicKey::from_bytes(public)
}

/// SecretKey helper
fn create_secret(secret: &[u8]) -> Result<SecretKey, SignatureError> {
    SecretKey::from_bytes(secret)
}

fn to_ed25519_bytes(secret: &[u8]) -> Result<[u8; 64], SignatureError> {
    SecretKey::from_bytes(secret).map(|s| s.to_ed25519_bytes())
}

fn from_ed25519_bytes(secret: &[u8]) -> Result<SecretKey, SignatureError> {
    SecretKey::from_ed25519_bytes(secret)
}

/// Size of input SEED for derivation, bytes
pub const SR25519_SEED_SIZE: c_ulong = 32;

/// Size of CHAINCODE, bytes
pub const SR25519_CHAINCODE_SIZE: c_ulong = 32;

/// Size of SR25519 PUBLIC KEY, bytes
pub const SR25519_PUBLIC_SIZE: c_ulong = 32;

/// Size of SR25519 PRIVATE (SECRET) KEY, which consists of [32 bytes key | 32 bytes nonce]
pub const SR25519_SECRET_SIZE: c_ulong = 64;

/// Size of SR25519 SIGNATURE, bytes
pub const SR25519_SIGNATURE_SIZE: c_ulong = 64;

/// Size of SR25519 KEYPAIR. [32 bytes key | 32 bytes nonce | 32 bytes public]
pub const SR25519_KEYPAIR_SIZE: c_ulong = 96;

/// Size of VRF output, bytes
pub const SR25519_VRF_OUTPUT_SIZE: c_ulong = 32;

/// Size of VRF proof, bytes
pub const SR25519_VRF_PROOF_SIZE: c_ulong = 64;

/// Size of VRF raw output, bytes
pub const SR25519_VRF_RAW_OUTPUT_SIZE: c_ulong = 16;

/// Size of VRF limit, bytes
pub const SR25519_VRF_THRESHOLD_SIZE: c_ulong = 16;


/// Creates public key from secret key
///
/// * pubkey_out: pre-allocated output buffer of SR25519_PUBLIC_SIZE bytes
/// * secret_ptr: secret key - input buffer of SR25519_SECRET_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_secret_to_public_key(
    pubkey_out: *mut u8,
    secret_ptr: *const u8
) -> Sr25519Result {
    let secret_bytes = slice::from_raw_parts(secret_ptr, SR25519_SECRET_SIZE as usize);
    let secret = match create_secret(secret_bytes) {
        Ok(s) => s,
        Err(err) => return convert_error(&err),
    };
    let p = secret.to_public();
    ptr::copy(p.to_bytes().as_ptr(), pubkey_out, SR25519_PUBLIC_SIZE as usize);
    Sr25519Result::Ok
}

/// Perform a derivation on a secret
///
/// * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_keypair_hard(
    keypair_out: *mut u8,
    pair_ptr: *const u8,
    cc_ptr: *const u8,
) -> Sr25519Result {
    let pair = slice::from_raw_parts(pair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE as usize);
    let kp = match create_from_pair(pair) {
        Ok(p) => p,
        Err(err) => return convert_error(&err),
    };
    let derived = kp.secret
        .hard_derive_mini_secret_key(Some(create_cc(cc)), &[])
        .0
        .expand_to_keypair(ExpansionMode::Ed25519);

    ptr::copy(derived.to_bytes().as_ptr(), keypair_out, SR25519_KEYPAIR_SIZE as usize);
    Sr25519Result::Ok
}

/// Perform a derivation on a secret
///
/// * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_keypair_soft(
    keypair_out: *mut u8,
    pair_ptr: *const u8,
    cc_ptr: *const u8,
) -> Sr25519Result {
    let pair = slice::from_raw_parts(pair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE as usize);
    let kp = match create_from_pair(pair) {
        Ok(p) => p,
        Err(err) => return convert_error(&err),
    };
    let derived = kp.derived_key_simple(create_cc(cc), &[]).0;

    ptr::copy(derived.to_bytes().as_ptr(), keypair_out, SR25519_KEYPAIR_SIZE as usize);
    Sr25519Result::Ok
}

/// Perform a derivation on a publicKey
///
/// * pubkey_out: pre-allocated output buffer of SR25519_PUBLIC_SIZE bytes
/// * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_public_soft(
    pubkey_out: *mut u8,
    public_ptr: *const u8,
    cc_ptr: *const u8,
) -> Sr25519Result {
    let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE as usize);
    let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE as usize);
    let p = match create_public(public) {
        Ok(pk) => pk,
        Err(err) => return convert_error(&err),
    };
    let derived = p.derived_key_simple(create_cc(cc), &[]).0;
    ptr::copy(derived.to_bytes().as_ptr(), pubkey_out, SR25519_PUBLIC_SIZE as usize);
    Sr25519Result::Ok
}

/// Generate a key pair.
///
/// * keypair_out: keypair [32b key | 32b nonce | 32b public], pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * seed: generation seed - input buffer of SR25519_SEED_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_keypair_from_seed(keypair_out: *mut u8, seed_ptr: *const u8) -> Sr25519Result {
    let seed = slice::from_raw_parts(seed_ptr, SR25519_SEED_SIZE as usize);
    let kp = match create_from_seed(seed) {
        Ok(kp) => kp,
        Err(err) => return convert_error(&err),
    };
    ptr::copy(kp.to_bytes().as_ptr(), keypair_out, SR25519_KEYPAIR_SIZE as usize);
    Sr25519Result::Ok
}

/// Converts secret key to ed25519 representation.
///
/// * secret_out: 64 bytes, pre-allocated output buffer of SR25519_SECRET_SIZE bytes
/// * secret_ptr: generation seed - input buffer of SR25519_SECRET_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_to_ed25519_bytes(secret_out: *mut u8, secret_ptr: *const u8) -> Sr25519Result {
    let secret = slice::from_raw_parts(secret_ptr, SR25519_SECRET_SIZE as usize);
    let bytes = match to_ed25519_bytes(secret) {
        Ok(b) => b,
        Err(err) => return convert_error(&err),
    };
    ptr::copy(bytes.as_ptr(), secret_out, SR25519_SECRET_SIZE as usize);
    Sr25519Result::Ok
}

/// Retrives secret key from ed25519 representation.
///
/// * secret_out: 64 bytes, pre-allocated output buffer of SR25519_SECRET_SIZE bytes
/// * secret_ptr: generation seed - input buffer of SR25519_SECRET_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_from_ed25519_bytes(secret_out: *mut u8, secret_ptr: *const u8) -> Sr25519Result {
    let secret = slice::from_raw_parts(secret_ptr, SR25519_SECRET_SIZE as usize);
    let sk = match from_ed25519_bytes(secret) {
        Ok(s) => s,
        Err(err) => return convert_error(&err),
    };
    ptr::copy(sk.to_bytes().as_ptr(), secret_out, SR25519_SECRET_SIZE as usize);
    Sr25519Result::Ok
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * signature_out: output buffer of ED25519_SIGNATURE_SIZE bytes
/// * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
/// * secret_ptr: private key (secret) - input buffer of SR25519_SECRET_SIZE bytes
/// * message_ptr: Arbitrary message; input buffer of size message_length
/// * message_length: Length of a message
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_sign(
    signature_out: *mut u8,
    public_ptr: *const u8,
    secret_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
) -> Sr25519Result {
    let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE as usize);
    let secret = slice::from_raw_parts(secret_ptr, SR25519_SECRET_SIZE as usize);
    let message = slice::from_raw_parts(message_ptr, message_length as usize);

    let sk = match create_secret(secret) {
        Ok(s) => s,
        Err(err) => return convert_error(&err),
    };
    let pk = match create_public(public) {
        Ok(p) => p,
        Err(err) => return convert_error(&err),
    };
    let sig = sk.sign_simple(SIGNING_CTX, message, &pk);

    ptr::copy(
        sig.to_bytes().as_ptr(),
        signature_out,
        SR25519_SIGNATURE_SIZE as usize,
    );
    Sr25519Result::Ok
}

/// Verify a message and its corresponding against a public key;
///
/// * signature_ptr: verify this signature
/// * message_ptr: Arbitrary message; input buffer of message_length bytes
/// * message_length: Message size
/// * public_ptr: verify with this public key; input buffer of SR25519_PUBLIC_SIZE bytes
///
/// * returned true if signature is valid, false otherwise
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_verify(
    signature_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
    public_ptr: *const u8,
) -> bool {
    let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE as usize);
    let signature = slice::from_raw_parts(signature_ptr, SR25519_SIGNATURE_SIZE as usize);
    let message = slice::from_raw_parts(message_ptr, message_length as usize);
    let signature = match Signature::from_bytes(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    let pk = match create_public(public) {
        Ok(p) => p,
        Err(_) => return false,
    };

    pk.verify_simple(SIGNING_CTX, message, &signature).is_ok()
}

#[repr(C)]
pub struct VrfResult {
    pub result: Sr25519Result,
    pub is_less: bool,
}

impl VrfResult {
    fn create_err(err: &SignatureError) -> VrfResult {
        VrfResult { is_less: false, result: convert_error(&err) }
    }

    fn create_val(is_less: bool) -> VrfResult {
        VrfResult { is_less, result: Sr25519Result::Ok }
    }
}

impl std::fmt::Debug for VrfResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str("VrfResult { ")?;
        f.write_str(self.is_less.to_string().as_str())?;
        f.write_str(", ")?;
        write!(f, "{:?}", self)?;
        f.write_str(" }")?;
        Result::Ok(())
    }
}

/// Sign the provided message using a Verifiable Random Function and
/// if the result is less than \param limit provide the proof
/// @param out_and_proof_ptr pointer to output array, where the VRF out and proof will be written
/// @param keypair_ptr byte representation of the keypair that will be used during signing
/// @param message_ptr byte array to be signed
/// @param limit_ptr byte array, must be 16 bytes long
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_sign_if_less(
    out_and_proof_ptr: *mut u8,
    keypair_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
    limit_ptr: *const u8,
) -> VrfResult {
    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let keypair = match create_from_pair(keypair_bytes) {
        Ok(kp) => kp,
        Err(err) => return VrfResult::create_err(&err),
    };
    let message = slice::from_raw_parts(message_ptr, message_length as usize);

    let limit = slice::from_raw_parts(limit_ptr, SR25519_VRF_THRESHOLD_SIZE as usize);
    let mut limit_arr: [u8; SR25519_VRF_THRESHOLD_SIZE as usize] = Default::default();
    limit_arr.copy_from_slice(&limit[0..SR25519_VRF_THRESHOLD_SIZE as usize]);

    let (io, proof, _) =
        keypair.vrf_sign(
            signing_context(SIGNING_CTX).bytes(message));
    let limit_int = u128::from_le_bytes(limit_arr);

    let raw_out_bytes = io.make_bytes::<[u8; SR25519_VRF_RAW_OUTPUT_SIZE as usize]>(BABE_VRF_PREFIX);
    let check = u128::from_le_bytes(raw_out_bytes) < limit_int;

    ptr::copy(io.to_output().as_bytes().as_ptr(), out_and_proof_ptr, SR25519_VRF_OUTPUT_SIZE as usize);
    ptr::copy(proof.to_bytes().as_ptr(), out_and_proof_ptr.add(SR25519_VRF_OUTPUT_SIZE as usize), SR25519_VRF_PROOF_SIZE as usize);
    if check {
        VrfResult::create_val(true)
    } else {
        VrfResult::create_val(false)
    }
}

/// Verify a signature produced by a VRF with its original input and the corresponding proof and
/// check if the result of the function is less than the threshold.
/// @note If errors, is_less field of the returned structure is not meant to contain a valid value
/// @param public_key_ptr byte representation of the public key that was used to sign the message
/// @param message_ptr the orignal signed message
/// @param output_ptr the signature
/// @param proof_ptr the proof of the signature
/// @param threshold_ptr the threshold to be compared against
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_verify(
    public_key_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
    output_ptr: *const u8,
    proof_ptr: *const u8,
    threshold_ptr: *const u8,
) -> VrfResult {
    let public_key = match create_public(slice::from_raw_parts(public_key_ptr, SR25519_PUBLIC_SIZE as usize)) {
        Ok(pk) => pk,
        Err(err) => return VrfResult::create_err(&err),
    };
    let message = slice::from_raw_parts(message_ptr, message_length as usize);
    let ctx = signing_context(SIGNING_CTX).bytes(message);
    let given_out = match VRFOutput::from_bytes(
        slice::from_raw_parts(output_ptr, SR25519_VRF_OUTPUT_SIZE as usize)) {
        Ok(val) => val,
        Err(err) => return VrfResult::create_err(&err)
    };
    let given_proof = match VRFProof::from_bytes(
        slice::from_raw_parts(proof_ptr, SR25519_VRF_PROOF_SIZE as usize)) {
        Ok(val) => val,
        Err(err) => return VrfResult::create_err(&err)
    };
    let (in_out, proof) =
        match public_key.vrf_verify(ctx.clone(), &given_out, &given_proof) {
            Ok(val) => val,
            Err(err) => return VrfResult::create_err(&err)
        };
    let raw_output = in_out.make_bytes::<[u8; SR25519_VRF_RAW_OUTPUT_SIZE as usize]>(BABE_VRF_PREFIX);

    let threshold = slice::from_raw_parts(threshold_ptr, SR25519_VRF_THRESHOLD_SIZE as usize);
    let mut threshold_arr: [u8; SR25519_VRF_THRESHOLD_SIZE as usize] = Default::default();
    threshold_arr.copy_from_slice(&threshold[0..SR25519_VRF_THRESHOLD_SIZE as usize]);
    let threshold_int = u128::from_le_bytes(threshold_arr);

    let check = u128::from_le_bytes(raw_output) < threshold_int;

    let decomp_proof = match
        proof.shorten_vrf(&public_key, ctx.clone(), &in_out.to_output()) {
        Ok(val) => val,
        Err(e) => return VrfResult::create_err(&e)
    };
    if in_out.to_output() == given_out &&
        decomp_proof == given_proof {
        VrfResult::create_val(check)
    } else {
        VrfResult::create_err(&SignatureError::EquationFalse)
    }
}

/// A key-value pair appended to a Merlin transcript, mirroring
/// `sp_core::sr25519::vrf::VrfTranscript::new(label, &[(key, value), ...])`.
#[repr(C)]
pub struct VrfTranscriptField {
    pub key: *const u8,
    pub key_length: c_ulong,
    pub value: *const u8,
    pub value_length: c_ulong,
}

/// Sign a VRF transcript built from a caller-supplied label and key-value fields.
///
/// Mirrors `VrfTranscript::new(label, &[(key, value), ...])` from sp_core.
///
/// @param out_ptr 96-byte output buffer = 32-byte pre-output followed by 64-byte proof
/// @param keypair_ptr 96-byte sr25519 keypair (64-byte secret followed by 32-byte public)
/// @param label_ptr transcript label bytes
/// @param label_length length of the label
/// @param fields_ptr array of VrfTranscriptField structs
/// @param fields_count number of fields
///
/// @return Sr25519Result::Ok on success, error code on failure
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_generic_vrf_sign(
    out_ptr: *mut u8,
    keypair_ptr: *const u8,
    label_ptr: *const u8,
    label_length: c_ulong,
    fields_ptr: *const VrfTranscriptField,
    fields_count: c_ulong,
) -> Sr25519Result {
    if out_ptr.is_null() || keypair_ptr.is_null() || label_ptr.is_null()
        || (fields_count > 0 && fields_ptr.is_null())
    {
        return Sr25519Result::BytesLengthError;
    }

    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let keypair = match Keypair::from_bytes(keypair_bytes) {
        Ok(kp) => kp,
        Err(err) => return convert_error(&err),
    };
    let label = slice::from_raw_parts(label_ptr, label_length as usize);

    let mut transcript = Transcript::new(label);
    if fields_count > 0 {
        let fields = slice::from_raw_parts(fields_ptr, fields_count as usize);
        for field in fields {
            if field.key.is_null() || field.value.is_null() {
                return Sr25519Result::BytesLengthError;
            }
            let key = slice::from_raw_parts(field.key, field.key_length as usize);
            let value = slice::from_raw_parts(field.value, field.value_length as usize);
            transcript.append_message(key, value);
        }
    }

    let (in_out, proof, _) = keypair.vrf_sign(transcript);

    ptr::copy(
        in_out.to_output().as_bytes().as_ptr(),
        out_ptr,
        SR25519_VRF_OUTPUT_SIZE as usize,
    );
    ptr::copy(
        proof.to_bytes().as_ptr(),
        out_ptr.add(SR25519_VRF_OUTPUT_SIZE as usize),
        SR25519_VRF_PROOF_SIZE as usize,
    );

    Sr25519Result::Ok
}

/// Verify a VRF signature produced by `sr25519_generic_vrf_sign`.
///
/// Reconstructs the same Merlin transcript from label and fields,
/// then verifies the pre-output + proof pair.
///
/// @param public_key_ptr 32-byte sr25519 public key
/// @param label_ptr transcript label bytes
/// @param label_length length of the label
/// @param fields_ptr array of VrfTranscriptField structs
/// @param fields_count number of fields
/// @param output_ptr 32-byte VRF pre-output
/// @param proof_ptr 64-byte VRF proof
///
/// @return Sr25519Result::Ok if valid, error code otherwise
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_generic_vrf_verify(
    public_key_ptr: *const u8,
    label_ptr: *const u8,
    label_length: c_ulong,
    fields_ptr: *const VrfTranscriptField,
    fields_count: c_ulong,
    output_ptr: *const u8,
    proof_ptr: *const u8,
) -> Sr25519Result {
    if public_key_ptr.is_null() || label_ptr.is_null()
        || (fields_count > 0 && fields_ptr.is_null())
        || output_ptr.is_null() || proof_ptr.is_null()
    {
        return Sr25519Result::BytesLengthError;
    }

    let public_key = match PublicKey::from_bytes(
        slice::from_raw_parts(public_key_ptr, SR25519_PUBLIC_SIZE as usize),
    ) {
        Ok(pk) => pk,
        Err(err) => return convert_error(&err),
    };
    let label = slice::from_raw_parts(label_ptr, label_length as usize);

    let given_out = match VRFOutput::from_bytes(
        slice::from_raw_parts(output_ptr, SR25519_VRF_OUTPUT_SIZE as usize),
    ) {
        Ok(val) => val,
        Err(err) => return convert_error(&err),
    };
    let given_proof = match VRFProof::from_bytes(
        slice::from_raw_parts(proof_ptr, SR25519_VRF_PROOF_SIZE as usize),
    ) {
        Ok(val) => val,
        Err(err) => return convert_error(&err),
    };

    let mut transcript = Transcript::new(label);
    if fields_count > 0 {
        let fields = slice::from_raw_parts(fields_ptr, fields_count as usize);
        for field in fields {
            if field.key.is_null() || field.value.is_null() {
                return Sr25519Result::BytesLengthError;
            }
            let key = slice::from_raw_parts(field.key, field.key_length as usize);
            let value = slice::from_raw_parts(field.value, field.value_length as usize);
            transcript.append_message(key, value);
        }
    }

    match public_key.vrf_verify(transcript, &given_out, &given_proof) {
        Ok(_) => Sr25519Result::Ok,
        Err(err) => convert_error(&err),
    }
}

#[cfg(test)]
pub mod tests {
    extern crate rand;
    extern crate schnorrkel;

    use super::*;

    use hex_literal::hex;
    use schnorrkel::{KEYPAIR_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

    fn generate_random_seed() -> Vec<u8> {
        (0..32).map(|_| rand::random::<u8>()).collect()
    }

    #[test]
    fn can_create_keypair() {
        let seed = generate_random_seed();
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let res = unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };

        assert_eq!(res, Sr25519Result::Ok);
        assert_eq!(keypair.len(), KEYPAIR_LENGTH);
    }

    #[test]
    fn creates_pair_from_known() {
        let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
        let expected = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let res = unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        assert_eq!(res, Sr25519Result::Ok);
        let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        assert_eq!(public, expected);
    }

    #[test]
    fn can_sign_message() {
        let seed = generate_random_seed();
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let private = &keypair[0..SECRET_KEY_LENGTH];
        let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
        let message = b"this is a message";

        let mut signature = [0u8; SR25519_SIGNATURE_SIZE as usize];
        let res = unsafe {
            sr25519_sign(
                signature.as_mut_ptr(),
                public.as_ptr(),
                private.as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
            )
        };

        assert_eq!(res, Sr25519Result::Ok);
        assert_eq!(signature.len(), SIGNATURE_LENGTH);
    }

    #[test]
    fn can_verify_message() {
        let seed = generate_random_seed();
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let private = &keypair[0..SECRET_KEY_LENGTH];
        let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
        let message = b"this is a message";
        let mut signature = [0u8; SR25519_SIGNATURE_SIZE as usize];
        unsafe {
            sr25519_sign(
                signature.as_mut_ptr(),
                public.as_ptr(),
                private.as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
            )
        };
        let is_valid = unsafe {
            sr25519_verify(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
                public.as_ptr(),
            )
        };

        assert!(is_valid);
    }

    #[test]
    fn soft_derives_pair() {
        let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
        let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
        let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let mut derived = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let res = unsafe { sr25519_derive_keypair_soft(derived.as_mut_ptr(), keypair.as_ptr(), cc.as_ptr()) };
        assert_eq!(res, Sr25519Result::Ok);
        let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        assert_eq!(public, expected);
    }

    #[test]
    fn soft_derives_public() {
        let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
        let public = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
        let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
        let mut derived = [0u8; SR25519_PUBLIC_SIZE as usize];
        let res = unsafe { sr25519_derive_public_soft(derived.as_mut_ptr(), public.as_ptr(), cc.as_ptr()) };
        assert_eq!(res, Sr25519Result::Ok);

        assert_eq!(derived, expected);
    }

    #[test]
    fn hard_derives_pair() {
        let cc = hex!("14416c6963650000000000000000000000000000000000000000000000000000"); // Alice
        let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
        let expected = hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let mut derived = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let res = unsafe { sr25519_derive_keypair_hard(derived.as_mut_ptr(), keypair.as_ptr(), cc.as_ptr()) };
        assert_eq!(res, Sr25519Result::Ok);
        let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        assert_eq!(public, expected);
    }

    #[test]
    fn derive_hard_rejects_invalid_keypair() {
        let bad_pair = [0xffu8; SR25519_KEYPAIR_SIZE as usize];
        let cc = [0u8; SR25519_CHAINCODE_SIZE as usize];
        let mut derived = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let res = unsafe { sr25519_derive_keypair_hard(derived.as_mut_ptr(), bad_pair.as_ptr(), cc.as_ptr()) };
        assert_ne!(res, Sr25519Result::Ok);
    }

    #[test]
    fn derive_soft_rejects_invalid_keypair() {
        let bad_pair = [0xffu8; SR25519_KEYPAIR_SIZE as usize];
        let cc = [0u8; SR25519_CHAINCODE_SIZE as usize];
        let mut derived = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let res = unsafe { sr25519_derive_keypair_soft(derived.as_mut_ptr(), bad_pair.as_ptr(), cc.as_ptr()) };
        assert_ne!(res, Sr25519Result::Ok);
    }

    #[test]
    fn derive_public_soft_rejects_invalid_public() {
        let bad_public = [0xffu8; SR25519_PUBLIC_SIZE as usize];
        let cc = [0u8; SR25519_CHAINCODE_SIZE as usize];
        let mut derived = [0u8; SR25519_PUBLIC_SIZE as usize];
        let res = unsafe { sr25519_derive_public_soft(derived.as_mut_ptr(), bad_public.as_ptr(), cc.as_ptr()) };
        assert_ne!(res, Sr25519Result::Ok);
    }

    #[test]
    fn verify_returns_false_for_invalid_public_key() {
        let bad_public = [0xffu8; SR25519_PUBLIC_SIZE as usize];
        let message = b"test";
        let signature = [0u8; SR25519_SIGNATURE_SIZE as usize];
        let result = unsafe {
            sr25519_verify(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
                bad_public.as_ptr(),
            )
        };
        assert!(!result);
    }

    #[test]
    fn vrf_verify() {
        let seed = generate_random_seed();
        let mut keypair_bytes = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair_bytes.as_mut_ptr(), seed.as_ptr()) };
        let private = &keypair_bytes[0..SECRET_KEY_LENGTH];
        let public = &keypair_bytes[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
        let message = b"Hello, world!";

        let keypair = Keypair::from_bytes(&keypair_bytes).expect("Keypair creation error");
        let ctx = signing_context(SIGNING_CTX).bytes(message);
        let (io, proof, _) = keypair.vrf_sign(ctx.clone());
        let (io_, proof_) = keypair.public.vrf_verify(ctx.clone(), &io.to_output(), &proof).expect("Verification error");
        assert_eq!(io_, io);
        let decomp_proof = proof_.shorten_vrf(
            &keypair.public, ctx.clone(), &io.to_output()).expect("Shorten VRF");
        assert_eq!(proof, decomp_proof);
        unsafe {
            let threshold_bytes = [0u8; SR25519_VRF_THRESHOLD_SIZE as usize];
            let res = sr25519_vrf_verify(public.as_ptr(),
                                         message.as_ptr(), message.len() as c_ulong,
                                         io.as_output_bytes().as_ptr(),
                                         proof.to_bytes().as_ptr(), threshold_bytes.as_ptr());
            assert_eq!(res.result, Sr25519Result::Ok);
        }
    }

    /// Helper to build a VrfTranscriptField for tests
    fn make_field<'a>(key: &'a [u8], value: &'a [u8]) -> VrfTranscriptField {
        VrfTranscriptField {
            key: key.as_ptr(),
            key_length: key.len() as c_ulong,
            value: value.as_ptr(),
            value_length: value.len() as c_ulong,
        }
    }

    #[test]
    fn generic_vrf_sign_produces_valid_output() {
        let seed = generate_random_seed();
        let mut keypair_bytes = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair_bytes.as_mut_ptr(), seed.as_ptr()) };

        let keypair = Keypair::from_bytes(&keypair_bytes).expect("keypair");
        let public_bytes = keypair.public.to_bytes();

        let label = b"pop:airdrop";
        let event_id = [42u8; 32];
        let domain = [label.as_ref(), event_id.as_ref()].concat();
        let fields = [make_field(b"domain", &domain), make_field(b"signer", &public_bytes)];
        let mut out = [0u8; (SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE) as usize];

        let res = unsafe {
            sr25519_generic_vrf_sign(
                out.as_mut_ptr(), keypair_bytes.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
            )
        };
        assert_eq!(res, Sr25519Result::Ok, "generic vrf sign must succeed");

        assert!(out[..SR25519_VRF_OUTPUT_SIZE as usize].iter().any(|&b| b != 0),
            "pre-output must not be all zeros");

        // Verify using schnorrkel directly: reconstruct the same transcript
        let mut transcript = Transcript::new(label);
        transcript.append_message(b"domain", &domain);
        transcript.append_message(b"signer", &public_bytes);

        let vrf_output = VRFOutput::from_bytes(&out[..SR25519_VRF_OUTPUT_SIZE as usize])
            .expect("output must be valid");
        let proof = VRFProof::from_bytes(&out[SR25519_VRF_OUTPUT_SIZE as usize..])
            .expect("proof must be valid");

        let (in_out, _) = keypair.public.vrf_verify(transcript, &vrf_output, &proof)
            .expect("VRF verification must succeed");
        assert_eq!(in_out.to_output(), vrf_output, "output must match after verification");
    }

    #[test]
    fn generic_vrf_sign_deterministic_for_same_inputs() {
        let seed: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let mut keypair_bytes = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair_bytes.as_mut_ptr(), seed.as_ptr()) };

        let label = b"my-label";
        let data = b"my-domain-data";
        let fields = [make_field(b"data", data)];
        let mut out1 = [0u8; (SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE) as usize];
        let mut out2 = [0u8; (SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE) as usize];

        unsafe {
            sr25519_generic_vrf_sign(
                out1.as_mut_ptr(), keypair_bytes.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
            );
            sr25519_generic_vrf_sign(
                out2.as_mut_ptr(), keypair_bytes.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
            );
        }

        assert_eq!(
            &out1[..SR25519_VRF_OUTPUT_SIZE as usize],
            &out2[..SR25519_VRF_OUTPUT_SIZE as usize],
            "VRF pre-output must be deterministic"
        );
    }

    #[test]
    fn generic_vrf_sign_rejects_null_pointers() {
        let mut out = [0u8; (SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE) as usize];
        let keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let label = b"label";
        let fields = [make_field(b"k", b"v")];

        unsafe {
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_sign(std::ptr::null_mut(), keypair.as_ptr(),
                label.as_ptr(), label.len() as c_ulong, fields.as_ptr(), fields.len() as c_ulong));
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_sign(out.as_mut_ptr(), std::ptr::null(),
                label.as_ptr(), label.len() as c_ulong, fields.as_ptr(), fields.len() as c_ulong));
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_sign(out.as_mut_ptr(), keypair.as_ptr(),
                std::ptr::null(), label.len() as c_ulong, fields.as_ptr(), fields.len() as c_ulong));
        }
    }

    #[test]
    fn generic_vrf_verify_roundtrip() {
        let seed = generate_random_seed();
        let mut keypair_bytes = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair_bytes.as_mut_ptr(), seed.as_ptr()) };
        let public = &keypair_bytes[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        let label = b"pop:airdrop";
        let event_id = [99u8; 32];
        let domain = [label.as_ref(), event_id.as_ref()].concat();
        let fields = [make_field(b"domain", &domain), make_field(b"signer", public)];
        let mut out = [0u8; (SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE) as usize];

        unsafe {
            assert_eq!(Sr25519Result::Ok, sr25519_generic_vrf_sign(
                out.as_mut_ptr(), keypair_bytes.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
            ));

            // Valid signature must verify
            assert_eq!(Sr25519Result::Ok, sr25519_generic_vrf_verify(
                public.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
                out.as_ptr(),
                out.as_ptr().add(SR25519_VRF_OUTPUT_SIZE as usize),
            ));

            // Wrong field value must fail
            let wrong_domain = b"wrong-domain";
            let wrong_fields = [make_field(b"domain", wrong_domain), make_field(b"signer", public)];
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_verify(
                public.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                wrong_fields.as_ptr(), wrong_fields.len() as c_ulong,
                out.as_ptr(),
                out.as_ptr().add(SR25519_VRF_OUTPUT_SIZE as usize),
            ));

            // Wrong label must fail
            let wrong_label = b"wrong:label";
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_verify(
                public.as_ptr(),
                wrong_label.as_ptr(), wrong_label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
                out.as_ptr(),
                out.as_ptr().add(SR25519_VRF_OUTPUT_SIZE as usize),
            ));

            // Wrong public key must fail
            let mut wrong_keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
            let other_seed = generate_random_seed();
            sr25519_keypair_from_seed(wrong_keypair.as_mut_ptr(), other_seed.as_ptr());
            let wrong_public = &wrong_keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_verify(
                wrong_public.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
                out.as_ptr(),
                out.as_ptr().add(SR25519_VRF_OUTPUT_SIZE as usize),
            ));
        }
    }

    #[test]
    fn generic_vrf_verify_rejects_null_pointers() {
        let public = [0u8; SR25519_PUBLIC_SIZE as usize];
        let label = b"label";
        let fields = [make_field(b"k", b"v")];
        let output = [0u8; SR25519_VRF_OUTPUT_SIZE as usize];
        let proof = [0u8; SR25519_VRF_PROOF_SIZE as usize];

        unsafe {
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_verify(std::ptr::null(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
                output.as_ptr(), proof.as_ptr()));
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_verify(public.as_ptr(),
                std::ptr::null(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
                output.as_ptr(), proof.as_ptr()));
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_verify(public.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
                std::ptr::null(), proof.as_ptr()));
            assert_ne!(Sr25519Result::Ok, sr25519_generic_vrf_verify(public.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                fields.as_ptr(), fields.len() as c_ulong,
                output.as_ptr(), std::ptr::null()));
        }
    }

    #[test]
    fn generic_vrf_sign_with_zero_fields() {
        let seed = generate_random_seed();
        let mut keypair_bytes = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair_bytes.as_mut_ptr(), seed.as_ptr()) };

        let label = b"empty-transcript";
        let mut out = [0u8; (SR25519_VRF_OUTPUT_SIZE + SR25519_VRF_PROOF_SIZE) as usize];

        let res = unsafe {
            sr25519_generic_vrf_sign(
                out.as_mut_ptr(), keypair_bytes.as_ptr(),
                label.as_ptr(), label.len() as c_ulong,
                std::ptr::null(), 0,
            )
        };
        assert_eq!(res, Sr25519Result::Ok, "signing with zero fields must succeed");
    }
}