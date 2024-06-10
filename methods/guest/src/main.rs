#![no_main]

use sha2::{Sha384, Digest};

use risc0_zkvm::guest::env;
use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};

fn compute_merkle_root(leaf: &Vec<u8>, merkle_path: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut current_hash: Vec<u8> = Sha384::digest(leaf).to_vec();

    for sibling in merkle_path {
        let mut hasher = Sha384::new();
        if current_hash < *sibling {
            hasher.update(&current_hash);
            hasher.update(&sibling);
        } else {
            hasher.update(&sibling);
            hasher.update(&current_hash);
        }
        current_hash = hasher.finalize().to_vec();
    }

    current_hash
}

risc0_zkvm::guest::entry!(main);
fn main() {
    let start = env::cycle_count();

    let (encoded_verifying_key, merkle_root, signature): (EncodedPoint, Vec<u8>, Signature) = env::read();
    let leaf_hash: Vec<u8> = env::read();
    let merkle_path: Vec<Vec<u8>> = env::read();

    let computed_root = compute_merkle_root(&leaf_hash, &merkle_path);
    let diff = env::cycle_count();
    env::log(&format!("cycle count after merkle root: {}", diff - start));

    assert_eq!(computed_root, merkle_root);

    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&merkle_root, &signature)
        .expect("ECDSA signature verification failed");

   
    // let public_inputs = PublicInputs {
    //     merkle_root: computed_root.to_vec().into(),
    //     leaf: private_inputs.leaf.to_vec().into(),
    //     pubkey: pubkey_bytes_compressed.into(),
    //     signature: signature_bytes_compressed.into()
    // };
    // // Commit to the public values of the program.
    // env::commit_slice(&public_inputs.abi_encode());

    // Commit to the journal the verifying key and `message that was signed.
    env::commit(&(encoded_verifying_key, merkle_root));

    let diff = env::cycle_count();
    env::log(&format!("total cycle count: {}", diff - start));
}