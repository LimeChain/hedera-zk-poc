include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    //use bls_signatures::{PublicKey, PrivateKey, Signature, Serialize};

    use risc0_zkvm::{default_executor, ExecutorEnv};
    use std::str::FromStr;
    
    use sha2::{Sha384, Digest};

    use serde::Serialize;

    // Function to verify a Merkle proof
    fn compute_merkle_root(leaf: FixedBytes<48>, merkle_path: [[u8; 48]; 256]) -> [u8; 48] {
        let mut hash = Sha384::digest(leaf.as_slice());
        
        for sibling in merkle_path {
            let sibling_slice = sibling.as_slice();
            let mut combined = Vec::with_capacity(96);
            if hash.as_slice() < sibling_slice {
                combined.extend_from_slice(&hash);
                combined.extend_from_slice(&sibling_slice);
            } else {
                combined.extend_from_slice(&sibling_slice);
                combined.extend_from_slice(&hash);
            }
            hash = Sha384::digest(&combined);
        }
        
        let mut result = [0u8; 48];
        result.copy_from_slice(hash.as_slice());
        result
    }


    #[derive(Debug, Serialize)]
    struct PrivateInputs {
        pub merkle_root: FixedBytes<48>,
        pub leaf: FixedBytes<48>,
        pub bls_pubkey: FixedBytes<48>, // BLS public key size will always be 48 bytes
        pub bls_signature: FixedBytes<96>, // BLS signature size will always be 96 bytes
        pub serialized_path: FixedBytes<12288> // 48 * 256 length
    }

    impl PrivateInputs {
        pub fn new(
            merkle_root: FixedBytes<48>,
            leaf: FixedBytes<48>,
            bls_pubkey: FixedBytes<48>,
            bls_signature: FixedBytes<96>,
            serialized_path: FixedBytes<12288>,
        ) -> Self {
            Self {
                merkle_root,
                leaf,
                bls_pubkey,
                bls_signature,
                serialized_path,
            }
        }
    
    }

    #[test]
    fn test_verify() {

        // Precomputed example inputs
        let leaf_data = b"example leaf data";
        let leaf_hash = Sha384::digest(leaf_data);
        let leaf = FixedBytes::<48>::from_slice(leaf_hash.as_slice());

        // 48 byte padded numbers 0 to 255 concatenated
        let serialized_path = FixedBytes::<12288>::from_str("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ab0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ad0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ae0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000af0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ba0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000be0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bf0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ce0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cf0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000da0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000db0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000df0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ea0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000eb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ec0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ed0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff00000000000000000000000000000000").unwrap();

        let merkle_path: [[u8; 48]; 256] = serialized_path.chunks_exact(48).map(|chunk| {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(chunk);
            arr
        }).collect::<Vec<[u8; 48]>>().try_into().unwrap();

        
        let computed_root: [u8; 48] = compute_merkle_root(leaf.clone(), merkle_path);
        println!("initial computed_root: {:?}", computed_root);

        let merkle_root = FixedBytes::<48>::new(computed_root);
        // let bls_privkey: PrivateKey = PrivateKey::generate(&mut rand::thread_rng());
        // let bls_pubkey: PublicKey = bls_privkey.public_key();
        // let bls_signature: Signature = bls_privkey.sign(&(merkle_root.as_slice()));

        let bls_pubkey = FixedBytes::<48>::from_str("af991965245f23d0e8c498f95fb0293c3923f9ff68b24b93866570f49d9eb66afc19f156934f80edd52f42c3dcf41784").unwrap();
        let bls_signature = FixedBytes::<96>::from_str("af08d283cbf25c4863294e49d08080b6bb9861e92d7ccc16434c4d355bf3c22f7858e7cb63fc3461d3250ce250822f9a1274952d7282c1f585a48b2572497c727beaf295ba817c5c112d5a4603c0fe864caeadab040c9ad5db47441ac8aef259").unwrap();
        
        let private_inputs = PrivateInputs::new(merkle_root, leaf, bls_pubkey, bls_signature, serialized_path);
        println!("{:?}", private_inputs);
    

        let env = ExecutorEnv::builder()
            .write(&private_inputs).unwrap()
            .build().unwrap();

        // NOTE: Use the executor to run tests without proving.
        let session_info = default_executor().execute(env, super::MAIN_ELF).unwrap();

        // Call the verification function
        // verify_commitment(tx_hash, l1_block_number, signed_commitment, sequencer_pubkey, sequencing_data);
    }
}
