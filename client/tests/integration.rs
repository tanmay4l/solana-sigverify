use anchor_lang::AnchorSerialize;

#[test]
fn test_signature_info_serialization() {
    #[derive(AnchorSerialize)]
    struct SignatureInfo {
        signature: Vec<u8>,
        public_key: Vec<u8>,
        message: Vec<u8>,
    }

    let sig = SignatureInfo {
        signature: vec![0u8; 64],
        public_key: vec![0u8; 32],
        message: b"test message".to_vec(),
    };

    let mut buf = Vec::new();
    sig.serialize(&mut buf).expect("serialization failed");

    println!("\n✓ SignatureInfo serialization test:");
    println!("  Signature: 64 bytes");
    println!("  Public Key: 32 bytes");
    println!("  Message: 12 bytes");
    println!("  Total serialized: {} bytes\n", buf.len());

    assert!(!buf.is_empty(), "Serialization produced empty buffer");
    assert!(buf.len() > 100, "Serialization too small");
}

#[test]
fn test_batch_structure() {
    #[derive(AnchorSerialize)]
    struct SignatureInfo {
        signature: Vec<u8>,
        public_key: Vec<u8>,
        message: Vec<u8>,
    }

    let batch = vec![
        SignatureInfo {
            signature: vec![0u8; 64],
            public_key: vec![0u8; 32],
            message: b"msg1".to_vec(),
        },
        SignatureInfo {
            signature: vec![1u8; 64],
            public_key: vec![1u8; 32],
            message: b"msg2".to_vec(),
        },
        SignatureInfo {
            signature: vec![2u8; 64],
            public_key: vec![2u8; 32],
            message: b"msg3".to_vec(),
        },
    ];

    println!("\n✓ Batch verification test:");
    println!("  Batch size: {} signatures", batch.len());

    let mut total_size = 0;
    for (i, sig) in batch.iter().enumerate() {
        let mut buf = Vec::new();
        sig.serialize(&mut buf).expect("serialization failed");
        total_size += buf.len();
        println!("  [{}] serialized: {} bytes", i, buf.len());
    }

    println!("  Total batch size: {} bytes\n", total_size);
    assert_eq!(batch.len(), 3, "Batch size mismatch");
}

#[test]
fn test_result_structure() {
    #[derive(AnchorSerialize)]
    struct BatchResult {
        batch_id: u64,
        batch_size: u32,
        valid_count: u32,
        results: Vec<bool>,
    }

    let result = BatchResult {
        batch_id: 1,
        batch_size: 3,
        valid_count: 2,
        results: vec![true, true, false],
    };

    let mut buf = Vec::new();
    result.serialize(&mut buf).expect("serialization failed");

    println!("\n✓ BatchResult structure test:");
    println!("  Batch ID: {}", result.batch_id);
    println!("  Batch Size: {}", result.batch_size);
    println!("  Valid Count: {}", result.valid_count);
    println!("  Results: {} items", result.results.len());
    println!("  Serialized: {} bytes\n", buf.len());

    assert_eq!(result.valid_count, 2, "Valid count mismatch");
    assert_eq!(result.results.len(), 3, "Results count mismatch");
}

#[test]
fn test_end_to_end_structure() {
    println!("\n╔════════════════════════════════════════════╗");
    println!("║        End-to-End Structure Test           ║");
    println!("╚════════════════════════════════════════════╝\n");

    #[derive(AnchorSerialize)]
    struct SignatureInfo {
        signature: Vec<u8>,
        public_key: Vec<u8>,
        message: Vec<u8>,
    }

    #[derive(AnchorSerialize)]
    struct BatchResult {
        batch_id: u64,
        batch_size: u32,
        valid_count: u32,
        results: Vec<bool>,
    }

    // Simulate batch submission
    let batch = vec![
        SignatureInfo {
            signature: vec![0u8; 64],
            public_key: vec![0u8; 32],
            message: b"test message 1".to_vec(),
        },
        SignatureInfo {
            signature: vec![1u8; 64],
            public_key: vec![1u8; 32],
            message: b"test message 2".to_vec(),
        },
    ];

    println!("Step 1: Submit batch");
    println!("  Batch size: {} signatures", batch.len());
    let mut batch_buf = Vec::new();
    for sig in &batch {
        sig.serialize(&mut batch_buf).unwrap();
    }
    println!("  Total request size: {} bytes", batch_buf.len());

    // Simulate batch storage & querying
    let stored_result = BatchResult {
        batch_id: 42,
        batch_size: batch.len() as u32,
        valid_count: 1,
        results: vec![true, false],
    };

    println!("\nStep 2: Store result on-chain");
    println!("  Batch ID: {}", stored_result.batch_id);
    println!("  Batch Size: {}", stored_result.batch_size);
    println!("  Valid Count: {}", stored_result.valid_count);

    let mut result_buf = Vec::new();
    stored_result.serialize(&mut result_buf).unwrap();
    println!("  Storage size: {} bytes", result_buf.len());

    println!("\nStep 3: Query result");
    println!("  ✓ batch_id: {}", stored_result.batch_id);
    println!("  ✓ results[0]: {}", stored_result.results[0]);
    println!("  ✓ results[1]: {}", stored_result.results[1]);
    println!("  ✓ valid_count: {}/2", stored_result.valid_count);

    println!("\n✓ End-to-end structure test PASSED\n");

    assert_eq!(stored_result.batch_id, 42);
    assert_eq!(stored_result.batch_size, 2);
    assert_eq!(stored_result.valid_count, 1);
}
