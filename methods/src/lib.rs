include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {
    // use risc0_groth16::docker::stark_to_snark;

    use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
    // use risc0_zkvm::{
    //     get_prover_server, recursion::identity_p254, CompactReceipt, ExecutorEnv, ExecutorImpl, InnerReceipt, ProverOpts, Receipt, VerifierContext
    // };
    use risc0_zkvm::sha::Digestible;
    
    use sha2::{Digest, Sha384};

    use k256::{
        ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
        EncodedPoint,
    };
    use rand_core::OsRng;

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

    #[test]
    fn test_verify() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .init();

        // Precomputed example inputs
        let leaf_data = b"example leaf data";
        let leaf_hash: Vec<u8> = Sha384::digest(leaf_data).to_vec();

        let mut merkle_path: Vec<Vec<u8>> = vec![vec![0; 48]; 32];
        // Fill merkle_path with values from 0 to 31
        for i in 0..32 {
            merkle_path[i][47] = i as u8;
        }

        let computed_root: Vec<u8> = compute_merkle_root(&leaf_hash,  &merkle_path);

        tracing::info!("computed_root: {:x?}", computed_root);
        tracing::info!("leaf_hash: {:x?}", leaf_hash);
        tracing::info!("merkle_path: {:x?}", merkle_path);

        // Generate a random secp256k1 keypair and sign the message.
        let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
        let signature: Signature = signing_key.sign(&computed_root);

        let signature_input = (signing_key.verifying_key().to_encoded_point(true), computed_root, signature);

        println!("{:?}", signature_input);
        tracing::info!("env");
        let env: ExecutorEnv = ExecutorEnv::builder()
            .write(&signature_input)
            .unwrap()
            .write(&leaf_hash)
            .unwrap()
            .write(&merkle_path)
            .unwrap()
            .build()
            .unwrap();

        let prover = default_prover();
        let receipt = prover.prove(env, super::MAIN_ELF).unwrap();

        receipt.verify(super::MAIN_ID).unwrap();

        let (receipt_verifying_key, receipt_message): (EncodedPoint, Vec<u8>) =
        receipt.journal.decode().unwrap();

        // println!(
        //     "Verified the signature over message {:?} with key {}",
        //     std::str::from_utf8(&receipt_message[..]).unwrap(),
        //     receipt_verifying_key,
        // );
        // let calldata = vec![
        //     Token::Bytes(receipt.journal.bytes.clone()),
        //     Token::FixedBytes(receipt.inner.get_claim().unwrap().post.digest().as_bytes().to_vec()),
        //     Token::Bytes(receipt.inner.succinct().unwrap().get_seal_bytes()),
        // ];
        // let output = hex::encode(ethers::abi::encode(&calldata));
    
        // // Forge test FFI calls expect hex encoded bytes sent to stdout
        // print!("{output}");
        // std::io::stdout()
        //     .flush()
        //     .context("failed to flush stdout buffer")
        //     .unwrap();

        // tracing::info!("exec");
        // let mut exec: ExecutorImpl = ExecutorImpl::from_elf(env, super::MAIN_ELF).unwrap();

        // // tracing::info!("session");
        // let session = exec.run().unwrap();    

        // tracing::info!("opts");
        // let opts: ProverOpts = ProverOpts::default();

        // tracing::info!("ctx");
        // let ctx: VerifierContext = VerifierContext::default();

        // tracing::info!("prover");
        // let prover = get_prover_server(&opts).unwrap();

        // tracing::info!("receipt");
        // let receipt = prover.prove_session(&ctx, &session).unwrap();

        // tracing::info!("claim");
        // let claim: risc0_zkvm::ReceiptClaim = receipt.get_claim().unwrap();
        
        // tracing::info!("composite_receipt");
        // let composite_receipt: &risc0_zkvm::CompositeReceipt = receipt.inner.composite().unwrap();
        
        // tracing::info!("succinct_receipt");
        // let succinct_receipt: risc0_zkvm::SuccinctReceipt = prover.compress(composite_receipt).unwrap();
        
        // tracing::info!("journal");
        // let journal: Vec<u8> = session.journal.unwrap().bytes;
    
        // tracing::info!("ident_receipt");
        // let ident_receipt: risc0_zkvm::SuccinctReceipt = identity_p254(&succinct_receipt).unwrap();
        
        // tracing::info!("seal_bytes");
        // let seal_bytes: Vec<u8> = ident_receipt.get_seal_bytes();
    
        // tracing::info!("stark-to-snark");
        // let seal = stark_to_snark(&seal_bytes).unwrap().to_vec();
    
        // //TODO:
        // tracing::info!("Receipt");
        // let receipt = Receipt::new(
        //     InnerReceipt::Compact(CompactReceipt {seal: seal.clone(), claim }),
        //     journal.clone()
        // );

        // tracing::info!("serialize");
        // // Serialize the struct to a JSON string
        // let serialized = serde_json::to_string_pretty(&receipt).unwrap();

        // // Create or open the file
        // let mut file = File::create("receipt.json").expect("Failed to create file");

        // tracing::info!("write to file");
        // // Write the serialized string to the file
        // file.write_all(serialized.as_bytes()).expect("Failed to write to file");

        // tracing::info!("post-state-digest");
        // tracing::info!("{}", receipt.inner.get_claim().unwrap().post.digest());

        // tracing::info!("journal");
        // let hex_journal: String = journal.clone().iter().map(|byte| format!("{:02x}", byte)).collect();
        // tracing::info!(hex_journal);

        // tracing::info!("seal");
        // let hex_seal: String = seal.clone().iter().map(|byte| format!("{:02x}", byte)).collect();
        // tracing::info!(hex_seal);

        // tracing::info!("verify");
        // receipt.verify(super::MAIN_ELF).unwrap();

    }
}