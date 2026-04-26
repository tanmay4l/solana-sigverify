// Minimal SDK for batch Ed25519 verification.
// Builds the precompile + verify_batch ixs callers need.

use anchor_lang::AnchorSerialize;
use ed25519_dalek::{Keypair, Signer};
use solana_sdk::ed25519_instruction;
use solana_sdk::hash::hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_program;
use solana_sdk::sysvar;

#[derive(AnchorSerialize)]
pub struct SignatureInfo {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
}

pub fn result_pda(payer: &Pubkey, program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"result", payer.as_ref()], program)
}

pub fn verify_batch_ix(
    program: Pubkey,
    payer: Pubkey,
    batch: &[SignatureInfo],
) -> Instruction {
    let (result, _) = result_pda(&payer, &program);
    let mut data = anchor_disc("verify_batch").to_vec();
    let len = batch.len() as u32;
    data.extend_from_slice(&len.to_le_bytes());
    for s in batch {
        s.serialize(&mut data).unwrap();
    }
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(result, false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(sysvar::instructions::ID, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

pub fn build_batch_tx(
    program: Pubkey,
    payer: Pubkey,
    keypairs: &[Keypair],
    messages: &[Vec<u8>],
) -> Vec<Instruction> {
    assert_eq!(keypairs.len(), messages.len(), "kp/msg count mismatch");
    let mut ixs: Vec<Instruction> = keypairs
        .iter()
        .zip(messages)
        .map(|(kp, msg)| ed25519_instruction::new_ed25519_instruction(kp, msg))
        .collect();
    let batch: Vec<SignatureInfo> = keypairs
        .iter()
        .zip(messages)
        .map(|(kp, msg)| SignatureInfo {
            signature: kp.sign(msg).to_bytes().to_vec(),
            public_key: kp.public.to_bytes().to_vec(),
            message: msg.clone(),
        })
        .collect();
    ixs.push(verify_batch_ix(program, payer, &batch));
    ixs
}

fn anchor_disc(name: &str) -> [u8; 8] {
    let h = hash(format!("global:{}", name).as_bytes());
    let mut d = [0u8; 8];
    d.copy_from_slice(&h.to_bytes()[..8]);
    d
}
