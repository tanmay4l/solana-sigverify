use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::pubkey::Pubkey;
use std::collections::HashSet;

declare_id!("4vH2fvTbfgtSwS4nNzUEfHXVRFhXKjhPiEmF9RXd3bVx");

const ED25519_PROGRAM_ID: [u8; 32] = [
    0xed, 0x25, 0x51, 0x9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
];

#[derive(PartialEq, AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub enum BatchStatus {
    Pending = 0,
    Verified = 1,
    Completed = 2,
}

#[program]
pub mod batch_sigverify {
    use super::*;

    pub fn verify_batch(ctx: Context<VerifyBatch>, batch: Vec<SignatureInfo>) -> Result<()> {
        require!(!batch.is_empty(), ErrorCode::EmptyBatch);
        require!(batch.len() <= 255, ErrorCode::BatchTooLarge);

        let mut results = Vec::with_capacity(batch.len());
        let mut valid_count = 0u32;
        let mut seen_hashes = HashSet::new();
        let mut duplicate_count = 0u32;

        for sig in batch.iter() {
            require_eq!(sig.signature.len(), 64, ErrorCode::InvalidSignatureLength);
            require_eq!(sig.public_key.len(), 32, ErrorCode::InvalidPublicKeyLength);

            let sig_hash = hash_signature(&sig.signature);

            if seen_hashes.contains(&sig_hash) {
                duplicate_count += 1;
                results.push(false);
                continue;
            }
            seen_hashes.insert(sig_hash);

            let is_valid = ed25519_verify(&sig.public_key, &sig.message, &sig.signature);
            if is_valid {
                valid_count += 1;
            }
            results.push(is_valid);
        }

        let result = &mut ctx.accounts.result;
        result.batch_id = result.batch_id.saturating_add(1);
        result.batch_size = batch.len() as u32;
        result.valid_count = valid_count;
        result.duplicate_count = duplicate_count;
        result.results = results;
        result.timestamp = Clock::get()?.unix_timestamp;
        result.status = BatchStatus::Completed;

        emit!(BatchVerifyEvent {
            batch_size: batch.len() as u32,
            valid_count,
            duplicate_count,
            timestamp: result.timestamp,
        });

        Ok(())
    }
}

fn ed25519_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    const SIG_OFFSET: u8 = 10;
    const SIG_SIZE: usize = 64;
    const PUBKEY_SIZE: usize = 32;

    let pubkey_offset = (SIG_OFFSET as usize + SIG_SIZE) as u8;
    let msg_offset = (pubkey_offset as usize + PUBKEY_SIZE) as u16;

    let mut data = Vec::with_capacity(10 + 64 + 32 + message.len());
    data.extend_from_slice(&(1u16).to_le_bytes());
    data.push(SIG_OFFSET);
    data.push(SIG_SIZE as u8);
    data.push(pubkey_offset);
    data.push(PUBKEY_SIZE as u8);
    data.extend_from_slice(&msg_offset.to_le_bytes());
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(signature);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(message);

    let ix = Instruction {
        program_id: Pubkey::from(ED25519_PROGRAM_ID),
        accounts: vec![],
        data,
    };

    anchor_lang::solana_program::program::invoke(&ix, &[]).is_ok()
}

fn hash_signature(sig: &[u8]) -> u64 {
    let mut hash: u64 = 0;
    for (i, &byte) in sig.iter().take(8).enumerate() {
        hash = hash.wrapping_add((byte as u64) << (i * 8));
    }
    hash
}

#[derive(Accounts)]
pub struct VerifyBatch<'info> {
    #[account(init, payer = payer, space = 8 + BatchResult::MAX_SIZE)]
    pub result: Account<'info, BatchResult>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct BatchResult {
    pub batch_id: u64,
    pub batch_size: u32,
    pub valid_count: u32,
    pub duplicate_count: u32,
    pub results: Vec<bool>,
    pub timestamp: i64,
    pub status: BatchStatus,
}

impl BatchResult {
    const MAX_SIZE: usize = 8 + 4 + 4 + 4 + 4 + (255 * 1) + 8 + 1;
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct SignatureInfo {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
}

#[event]
pub struct BatchVerifyEvent {
    pub batch_size: u32,
    pub valid_count: u32,
    pub duplicate_count: u32,
    pub timestamp: i64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid signature length")]
    InvalidSignatureLength,
    #[msg("Invalid public key length")]
    InvalidPublicKeyLength,
    #[msg("Empty batch")]
    EmptyBatch,
    #[msg("Batch too large")]
    BatchTooLarge,
}
