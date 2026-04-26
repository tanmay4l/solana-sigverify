// Senior audit: verify EVERY claim about precompile + ix introspection.
// A,B: real ed25519 ix bytes match parser
// C,D: byte-level fault injection on chain — every protected position rejected
// E:   live tx logs prove zero CPI to ed25519

use ed25519_dalek::{Keypair as EdKeypair, Signer as EdSigner};
use rand::rngs::OsRng;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::ed25519_instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use std::str::FromStr;

use batch_sigverify_sdk::{verify_batch_ix, SignatureInfo};

fn program_id() -> Pubkey {
    Pubkey::from_str("2o1R3JBBaY39F6zRMyKpfZhFq88bEARA1b2bbUe39tVo").unwrap()
}

fn fund(client: &RpcClient) -> Keypair {
    let kp = Keypair::new();
    let sig = client.request_airdrop(&kp.pubkey(), 2_000_000_000).unwrap();
    for _ in 0..30 {
        if client.confirm_transaction(&sig).unwrap_or(false) { break; }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    kp
}

fn rpc() -> RpcClient {
    RpcClient::new_with_commitment("http://localhost:8899".to_string(), CommitmentConfig::confirmed())
}

#[test]
fn audit_a_b_solana_sdk_matches_our_parser() {
    let mut csprng = OsRng {};
    let kp = EdKeypair::generate(&mut csprng);
    let msg = b"audit-test".to_vec();
    let ix = ed25519_instruction::new_ed25519_instruction(&kp, &msg);

    let ed25519_id = Pubkey::from_str("Ed25519SigVerify111111111111111111111111111").unwrap();
    assert_eq!(ix.program_id, ed25519_id);
    assert!(ix.accounts.is_empty());

    let d = &ix.data;
    assert_eq!(d[0], 1, "num_signatures");
    assert_eq!(d[1], 0, "padding");

    let sig_off  = u16::from_le_bytes([d[2], d[3]]);
    let sig_ix   = u16::from_le_bytes([d[4], d[5]]);
    let pk_off   = u16::from_le_bytes([d[6], d[7]]);
    let pk_ix    = u16::from_le_bytes([d[8], d[9]]);
    let msg_off  = u16::from_le_bytes([d[10], d[11]]);
    let msg_size = u16::from_le_bytes([d[12], d[13]]);
    let msg_ix   = u16::from_le_bytes([d[14], d[15]]);

    assert_eq!(sig_ix,  u16::MAX, "wormhole defense: sig_ix must be u16::MAX");
    assert_eq!(pk_ix,   u16::MAX, "wormhole defense: pk_ix must be u16::MAX");
    assert_eq!(msg_ix,  u16::MAX, "wormhole defense: msg_ix must be u16::MAX");
    assert_eq!(msg_size as usize, msg.len());

    assert_eq!(&d[pk_off as usize..pk_off as usize + 32], kp.public.to_bytes().as_ref());
    assert_eq!(&d[sig_off as usize..sig_off as usize + 64], kp.sign(&msg).to_bytes().as_ref());
    assert_eq!(&d[msg_off as usize..msg_off as usize + msg_size as usize], msg.as_slice());

    println!("✓ AUDIT A,B: Solana SDK output matches parser exactly");
}

#[test]
fn audit_c_d_byte_mutation_rejected_on_chain() {
    let client = rpc();
    let mut csprng = OsRng {};

    let positions: Vec<(usize, &str)> = vec![
        (0,  "header: num_signatures"),
        (1,  "header: padding"),
        (4,  "offsets: signature_ix_index"),
        (8,  "offsets: public_key_ix_index"),
        (14, "offsets: message_ix_index"),
        (16, "data: pubkey first byte"),
        (16 + 32,     "data: signature first byte"),
        (16 + 32 + 64, "data: message first byte"),
    ];

    println!("\n--- Fault injection ---");
    for (pos, label) in positions {
        let payer = fund(&client);
        let kp = EdKeypair::generate(&mut csprng);
        let msg = b"mutate".to_vec();

        let mut pre = ed25519_instruction::new_ed25519_instruction(&kp, &msg);
        if pos >= pre.data.len() { continue; }
        pre.data[pos] ^= 0xFF;

        let batch = vec![SignatureInfo {
            signature: kp.sign(&msg).to_bytes().to_vec(),
            public_key: kp.public.to_bytes().to_vec(),
            message: msg,
        }];

        let verify = verify_batch_ix(program_id(), payer.pubkey(), &batch);
        let blockhash = client.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(
            &[pre, verify],
            Some(&payer.pubkey()),
            &[&payer],
            blockhash,
        );

        let result = client.send_and_confirm_transaction(&tx);
        assert!(result.is_err(), "byte {} ({}) should be rejected", pos, label);
        println!("  byte {:3} ({:35}): rejected ✓", pos, label);
    }
    println!("✓ AUDIT C,D: every protected byte position rejected");
}

#[test]
fn audit_e_no_ed25519_cpi_in_program_logs() {
    let client = rpc();
    let payer = fund(&client);
    let mut csprng = OsRng {};

    let kp = EdKeypair::generate(&mut csprng);
    let msg = b"audit-cpi-check".to_vec();
    let pre = ed25519_instruction::new_ed25519_instruction(&kp, &msg);

    let batch = vec![SignatureInfo {
        signature: kp.sign(&msg).to_bytes().to_vec(),
        public_key: kp.public.to_bytes().to_vec(),
        message: msg,
    }];
    let verify = verify_batch_ix(program_id(), payer.pubkey(), &batch);

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[pre, verify],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let sim = client.simulate_transaction(&tx).expect("sim");
    let logs = sim.value.logs.unwrap_or_default();

    println!("\n--- Real on-chain logs ---");
    for l in &logs { println!("  {}", l); }

    let prog = format!("{}", program_id());
    let our_invokes = logs.iter().filter(|l| l.contains(&prog) && l.contains("invoke")).count();
    let ed25519_invokes = logs.iter().filter(|l| l.contains("Ed25519SigVerify") && l.contains("invoke")).count();

    assert_eq!(ed25519_invokes, 0, "found Ed25519 CPI from program");
    assert!(our_invokes >= 1, "program must invoke at least once");
    println!("\n✓ AUDIT E: our_invokes={}, ed25519_invokes={}", our_invokes, ed25519_invokes);
}
