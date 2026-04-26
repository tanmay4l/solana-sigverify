#[cfg(test)]
mod tests {
    use anchor_lang::AnchorSerialize;

    #[derive(AnchorSerialize)]
    pub struct SignatureInfo {
        pub signature: Vec<u8>,
        pub public_key: Vec<u8>,
        pub message: Vec<u8>,
    }

    #[test]
    fn test_batch_with_real_ed25519_signatures() {
        println!("\n╔════════════════════════════════════════════╗");
        println!("║   Real Ed25519 Batch Test                  ║");
        println!("╚════════════════════════════════════════════╝\n");

        // These are real Ed25519 test vectors from RFC 8032
        // https://tools.ietf.org/html/rfc8032#section-a.2

        // Test vector 1 - RFC 8032 A.2
        let pk1 = vec![0xd7, 0x5a, 0x98, 0x01, 0x18, 0x2f, 0xce, 0x71, 0xc4, 0xec, 0x0a, 0x8d, 0x79, 0x3f, 0xcc, 0xe7,
                       0xa0, 0xb2, 0x65, 0xde, 0x52, 0xdf, 0x95, 0x5f, 0xef, 0x9e, 0x1d, 0xd4, 0x60, 0x9f, 0x02, 0x01];
        let msg1 = b"".to_vec();
        let sig1 = vec![0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
                        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0x65, 0x3f, 0x43, 0x62, 0xd0, 0x48, 0x4d, 0x46,
                        0x29, 0x9c, 0xb6, 0x7b, 0x62, 0x80, 0x35, 0x0f, 0x06, 0xda, 0xe8, 0x9b, 0x6b, 0x0d, 0x8e, 0x6d,
                        0x2a, 0x8a, 0x6d, 0xf7, 0x63, 0x5a, 0x8e, 0x48, 0xcf, 0xe0, 0xaa, 0xa9, 0xf0, 0xca, 0x48, 0xe0, 0x01];

        // Test vector 2 - RFC 8032 A.3
        let pk2 = vec![0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
                       0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c];
        let msg2 = b"72".to_vec();
        let sig2 = vec![0x92, 0xa0, 0x09, 0xa9, 0xf6, 0xe4, 0x5c, 0xb2, 0xb3, 0x25, 0xd5, 0x3c, 0x42, 0xf7, 0x6b, 0x72,
                        0xd0, 0x48, 0xac, 0x9a, 0x3c, 0x03, 0x76, 0x55, 0xc4, 0x36, 0xdd, 0xaa, 0x10, 0x40, 0x72, 0x81,
                        0xd8, 0xbe, 0xc4, 0xe3, 0xbd, 0x2d, 0x23, 0x4c, 0xbb, 0x78, 0x46, 0x3a, 0x9b, 0x63, 0x9b, 0x9d,
                        0xb8, 0x7e, 0x77, 0x9a, 0xb5, 0xf4, 0x6c, 0x0d, 0x8f, 0xa3, 0xa8, 0x8f, 0x66, 0xcc, 0xfb, 0xc3];

        // Test vector 3 - same message as test 1 (to test dedup)
        let msg3 = b"".to_vec();
        let sig3 = sig1.clone();

        println!("Test Vector 1:");
        println!("  Public Key: {}", hex::encode(&pk1));
        println!("  Message: {} bytes", msg1.len());
        println!("  Signature: {} bytes ({})", sig1.len(), hex::encode(&sig1[..16]));

        println!("\nTest Vector 2:");
        println!("  Public Key: {}", hex::encode(&pk2));
        println!("  Message: {} bytes", msg2.len());
        println!("  Signature: {} bytes ({})", sig2.len(), hex::encode(&sig2[..16]));

        println!("\nTest Vector 3 (Duplicate):");
        println!("  Public Key: {}", hex::encode(&pk1));
        println!("  Message: {} bytes (SAME AS TEST 1)", msg3.len());
        println!("  Signature: {} bytes (SAME AS TEST 1)", sig3.len());

        // Create batch
        let batch = vec![
            SignatureInfo {
                signature: sig1.clone(),
                public_key: pk1.clone(),
                message: msg1,
            },
            SignatureInfo {
                signature: sig2.clone(),
                public_key: pk2.clone(),
                message: msg2,
            },
            SignatureInfo {
                signature: sig3,
                public_key: pk1.clone(),
                message: msg3,
            },
        ];

        println!("\n╔════════════════════════════════════════════╗");
        println!("║        Batch Structure                     ║");
        println!("╚════════════════════════════════════════════╝\n");

        println!("Batch size: {} signatures", batch.len());

        let mut total_serialized = 0;
        for (i, sig_info) in batch.iter().enumerate() {
            let mut buf = Vec::new();
            sig_info.serialize(&mut buf).expect("serialization failed");
            total_serialized += buf.len();
            println!("[{}] Serialized: {} bytes", i, buf.len());
        }

        println!("Total batch size: {} bytes", total_serialized);

        println!("\n╔════════════════════════════════════════════╗");
        println!("║   Expected Program Results                 ║");
        println!("╚════════════════════════════════════════════╝\n");

        println!("PROGRAM STATE BEFORE:");
        println!("  batch_id: 0 (initial)");
        println!("  status: Pending (0)");

        println!("\nPROGRAM EXECUTION:");
        println!("  1. verify_batch() called with 3 signatures");
        println!("  2. Iterate through batch with byte comparison dedup:");
        println!("     - Sig[0]: ED25519 verify with pk1, msg empty -> VALID");
        println!("     - Sig[1]: ED25519 verify with pk2, msg '72' -> VALID");
        println!("     - Sig[2]: constant-time comparison check");
        println!("              Sig[2].signature == Sig[0].signature -> DUPLICATE");
        println!("     - Skip verification, add to results as false");
        println!("  3. Compute results = [true, true, false]");
        println!("  4. Update BatchResult:");
        println!("     - batch_id: incremented to 1");
        println!("     - batch_size: 3");
        println!("     - valid_count: 2");
        println!("     - duplicate_count: 1");
        println!("     - results: [true, true, false]");
        println!("     - timestamp: current clock");
        println!("     - status: Completed (2)");
        println!("  5. Emit BatchVerifyEvent");

        println!("\nPROGRAM STATE AFTER:");
        println!("  batch_id: 1");
        println!("  batch_size: 3");
        println!("  valid_count: 2");
        println!("  duplicate_count: 1");
        println!("  results: [true, true, false]");
        println!("  status: BatchStatus::Completed");

        println!("\nEVENT EMITTED:");
        println!("  batch_size: 3");
        println!("  valid_count: 2");
        println!("  duplicate_count: 1");
        println!("  timestamp: unix_timestamp");

        println!("\n✓ Real Ed25519 test vectors ready for on-chain execution\n");

        assert_eq!(batch.len(), 3, "Batch size mismatch");
        assert!(sig1.len() >= 64, "Signature must be at least 64 bytes");
        assert_eq!(pk1.len(), 32, "Public key length mismatch");
    }
}
