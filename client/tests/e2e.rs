use anchor_lang::AnchorSerialize;
use borsh::BorshDeserialize;
use ed25519_dalek::{Keypair as EdKeypair, Signer as EdSigner};
use rand::rngs::OsRng;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::ed25519_instruction;
use solana_sdk::hash::hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::system_program;
use solana_sdk::sysvar;
use solana_sdk::transaction::Transaction;
use std::str::FromStr;

fn program_id() -> Pubkey {
    Pubkey::from_str("2o1R3JBBaY39F6zRMyKpfZhFq88bEARA1b2bbUe39tVo").unwrap()
}

fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let preimage = format!("global:{}", name);
    let h = hash(preimage.as_bytes());
    let mut d = [0u8; 8];
    d.copy_from_slice(&h.to_bytes()[..8]);
    d
}

#[derive(AnchorSerialize)]
struct SignatureInfoArg {
    signature: Vec<u8>,
    public_key: Vec<u8>,
    message: Vec<u8>,
}

#[derive(BorshDeserialize, Debug)]
struct BatchResultData {
    batch_id: u64,
    batch_size: u32,
    valid_count: u32,
    duplicate_count: u32,
    results: Vec<bool>,
    timestamp: i64,
    status: u8,
    bump: u8,
}

fn build_verify_batch_ix(
    program: Pubkey,
    payer: Pubkey,
    result_pda: Pubkey,
    batch: &[SignatureInfoArg],
) -> Instruction {
    let mut data = anchor_ix_disc("verify_batch").to_vec();
    let len = batch.len() as u32;
    data.extend_from_slice(&len.to_le_bytes());
    for s in batch {
        s.serialize(&mut data).unwrap();
    }

    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(result_pda, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

fn fresh_payer(client: &RpcClient) -> Keypair {
    let kp = Keypair::new();
    let sig = client
        .request_airdrop(&kp.pubkey(), 2_000_000_000)
        .expect("airdrop");
    for _ in 0..30 {
        if client.confirm_transaction(&sig).unwrap_or(false) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    kp
}

fn rpc() -> RpcClient {
    RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    )
}

#[test]
fn e2e_happy_path_two_sigs() {
    let client = rpc();
    let payer = fresh_payer(&client);

    let mut csprng = OsRng {};
    let kp1 = EdKeypair::generate(&mut csprng);
    let kp2 = EdKeypair::generate(&mut csprng);
    let msg1 = b"e2e message one".to_vec();
    let msg2 = b"e2e message two".to_vec();
    let sig1 = kp1.sign(&msg1).to_bytes().to_vec();
    let sig2 = kp2.sign(&msg2).to_bytes().to_vec();

    let pre1 = ed25519_instruction::new_ed25519_instruction(&kp1, &msg1);
    let pre2 = ed25519_instruction::new_ed25519_instruction(&kp2, &msg2);

    let (result_pda, _bump) = Pubkey::find_program_address(
        &[b"result", payer.pubkey().as_ref()],
        &program_id(),
    );

    let batch = vec![
        SignatureInfoArg {
            signature: sig1,
            public_key: kp1.public.to_bytes().to_vec(),
            message: msg1,
        },
        SignatureInfoArg {
            signature: sig2,
            public_key: kp2.public.to_bytes().to_vec(),
            message: msg2,
        },
    ];

    let verify_ix = build_verify_batch_ix(program_id(), payer.pubkey(), result_pda, &batch);

    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[pre1, pre2, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    client
        .send_and_confirm_transaction(&tx)
        .expect("verify_batch tx");

    let acct = client.get_account(&result_pda).expect("result acct");
    let mut slice = &acct.data[8..];
    let res = BatchResultData::deserialize(&mut slice).expect("decode");

    assert_eq!(res.batch_size, 2);
    assert_eq!(res.valid_count, 2);
    assert_eq!(res.duplicate_count, 0);
    assert_eq!(res.results, vec![true, true]);
    assert_eq!(res.status, 2);
    assert_eq!(res.batch_id, 1);
    println!("✓ Happy path: {:?}", res);
}

#[test]
fn e2e_duplicate_detection() {
    let client = rpc();
    let payer = fresh_payer(&client);

    let mut csprng = OsRng {};
    let kp = EdKeypair::generate(&mut csprng);
    let msg = b"dup msg".to_vec();
    let sig = kp.sign(&msg).to_bytes().to_vec();

    let pre = ed25519_instruction::new_ed25519_instruction(&kp, &msg);

    let (result_pda, _) = Pubkey::find_program_address(
        &[b"result", payer.pubkey().as_ref()],
        &program_id(),
    );

    let batch = vec![
        SignatureInfoArg {
            signature: sig.clone(),
            public_key: kp.public.to_bytes().to_vec(),
            message: msg.clone(),
        },
        SignatureInfoArg {
            signature: sig,
            public_key: kp.public.to_bytes().to_vec(),
            message: msg,
        },
    ];

    let verify_ix = build_verify_batch_ix(program_id(), payer.pubkey(), result_pda, &batch);

    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[pre, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    client
        .send_and_confirm_transaction(&tx)
        .expect("dup tx");

    let acct = client.get_account(&result_pda).expect("result acct");
    let mut slice = &acct.data[8..];
    let res = BatchResultData::deserialize(&mut slice).expect("decode");

    assert_eq!(res.batch_size, 2);
    assert_eq!(res.valid_count, 1);
    assert_eq!(res.duplicate_count, 1);
    assert_eq!(res.results, vec![true, false]);
    println!("✓ Dedup: {:?}", res);
}

#[test]
fn e2e_missing_precompile_fails() {
    let client = rpc();
    let payer = fresh_payer(&client);

    let mut csprng = OsRng {};
    let kp = EdKeypair::generate(&mut csprng);
    let msg = b"orphan".to_vec();
    let sig = kp.sign(&msg).to_bytes().to_vec();

    let (result_pda, _) = Pubkey::find_program_address(
        &[b"result", payer.pubkey().as_ref()],
        &program_id(),
    );

    let batch = vec![SignatureInfoArg {
        signature: sig,
        public_key: kp.public.to_bytes().to_vec(),
        message: msg,
    }];

    let verify_ix = build_verify_batch_ix(program_id(), payer.pubkey(), result_pda, &batch);

    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let res = client.send_and_confirm_transaction(&tx);
    let err = res.expect_err("expected tx to fail without precompile");
    let msg = format!("{:?}", err);
    assert!(msg.contains("Custom(6004)") || msg.contains("WrongPrecompileProgram"),
        "expected WrongPrecompileProgram (6004), got: {}", msg);
    println!("✓ Missing precompile rejected with WrongPrecompileProgram (6004)");
}

#[test]
fn e2e_wormhole_attack_rejected() {
    let client = rpc();
    let payer = fresh_payer(&client);

    let mut csprng = OsRng {};
    let kp = EdKeypair::generate(&mut csprng);
    let msg = b"attack target".to_vec();
    let sig = kp.sign(&msg).to_bytes().to_vec();

    let mut malicious_pre = ed25519_instruction::new_ed25519_instruction(&kp, &msg);
    malicious_pre.data[4] = 0;
    malicious_pre.data[5] = 0;

    let (result_pda, _) = Pubkey::find_program_address(
        &[b"result", payer.pubkey().as_ref()],
        &program_id(),
    );

    let batch = vec![SignatureInfoArg {
        signature: sig,
        public_key: kp.public.to_bytes().to_vec(),
        message: msg,
    }];

    let verify_ix = build_verify_batch_ix(program_id(), payer.pubkey(), result_pda, &batch);

    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[malicious_pre, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let res = client.send_and_confirm_transaction(&tx);
    let err = res.expect_err("expected wormhole-style attack to be rejected");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("Custom(6009)") || msg.contains("WrongInstructionIndex"),
        "expected WrongInstructionIndex (6009), got: {}", msg
    );
    println!("Wormhole-style attack rejected (non-MAX instruction_index)");
}

#[test]
fn e2e_too_few_precompile_ixs_fails() {
    let client = rpc();
    let payer = fresh_payer(&client);

    let mut csprng = OsRng {};
    let kp1 = EdKeypair::generate(&mut csprng);
    let kp2 = EdKeypair::generate(&mut csprng);
    let msg1 = b"first".to_vec();
    let msg2 = b"second".to_vec();
    let sig1 = kp1.sign(&msg1).to_bytes().to_vec();
    let sig2 = kp2.sign(&msg2).to_bytes().to_vec();

    let pre1 = ed25519_instruction::new_ed25519_instruction(&kp1, &msg1);

    let (result_pda, _) = Pubkey::find_program_address(
        &[b"result", payer.pubkey().as_ref()],
        &program_id(),
    );

    let batch = vec![
        SignatureInfoArg {
            signature: sig1,
            public_key: kp1.public.to_bytes().to_vec(),
            message: msg1,
        },
        SignatureInfoArg {
            signature: sig2,
            public_key: kp2.public.to_bytes().to_vec(),
            message: msg2,
        },
    ];

    let verify_ix = build_verify_batch_ix(program_id(), payer.pubkey(), result_pda, &batch);

    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[pre1, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let res = client.send_and_confirm_transaction(&tx);
    let err = res.expect_err("expected too-few-precompiles to fail");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("Custom(6004)") || msg.contains("WrongPrecompileProgram"),
        "expected WrongPrecompileProgram (6004), got: {}", msg
    );
    println!("Too-few-precompiles rejected with WrongPrecompileProgram (6004)");
}

fn cu_for_n_sigs(client: &RpcClient, n: usize) -> Option<u64> {
    let payer = fresh_payer(client);
    let mut csprng = OsRng {};

    let mut precompiles = Vec::with_capacity(n);
    let mut batch = Vec::with_capacity(n);
    for i in 0..n {
        let kp = EdKeypair::generate(&mut csprng);
        let msg = format!("b{}", i).into_bytes();
        let sig = kp.sign(&msg).to_bytes().to_vec();
        precompiles.push(ed25519_instruction::new_ed25519_instruction(&kp, &msg));
        batch.push(SignatureInfoArg {
            signature: sig,
            public_key: kp.public.to_bytes().to_vec(),
            message: msg,
        });
    }

    let (result_pda, _) = Pubkey::find_program_address(
        &[b"result", payer.pubkey().as_ref()],
        &program_id(),
    );

    let verify_ix = build_verify_batch_ix(program_id(), payer.pubkey(), result_pda, &batch);

    let mut ixs = precompiles;
    ixs.push(verify_ix);

    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    client.simulate_transaction(&tx).ok().and_then(|s| s.value.units_consumed)
}

#[test]
fn e2e_cu_scaling_benchmark() {
    let client = rpc();
    println!("\n  CU usage by batch size (legacy tx, 1232-byte limit):");
    for n in [1usize, 2, 3, 4] {
        match cu_for_n_sigs(&client, n) {
            Some(cu) => {
                let per_sig = cu as f64 / n as f64;
                println!("    {} sigs -> {} CU total ({:.0} CU/sig)", n, cu, per_sig);
            }
            None => {
                println!("    {} sigs -> EXCEEDS tx size limit (need v0 tx + LUTs)", n);
            }
        }
    }
}
