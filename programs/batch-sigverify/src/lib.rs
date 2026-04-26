use anchor_lang::prelude::*;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::sysvar::instructions::{
    self as ix_sysvar, load_instruction_at_checked,
};

declare_id!("2o1R3JBBaY39F6zRMyKpfZhFq88bEARA1b2bbUe39tVo");

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

        let ix_sysvar_ai = &ctx.accounts.instructions;
        let mut results = Vec::with_capacity(batch.len());
        let mut valid_count = 0u32;
        let mut duplicate_count = 0u32;
        let mut precompile_cursor: usize = 0;

        for (i, sig) in batch.iter().enumerate() {
            require_eq!(sig.signature.len(), 64, ErrorCode::InvalidSignatureLength);
            require_eq!(sig.public_key.len(), 32, ErrorCode::InvalidPublicKeyLength);

            let mut is_duplicate = false;
            for prev in batch.iter().take(i) {
                if prev.signature == sig.signature {
                    is_duplicate = true;
                    break;
                }
            }

            if is_duplicate {
                duplicate_count += 1;
                results.push(false);
                continue;
            }

            let ix = load_instruction_at_checked(precompile_cursor, ix_sysvar_ai)?;
            check_ed25519_data(&ix, &sig.public_key, &sig.signature, &sig.message)?;
            precompile_cursor += 1;
            valid_count += 1;
            results.push(true);
        }

        let result = &mut ctx.accounts.result;
        result.batch_id = result.batch_id.saturating_add(1);
        result.batch_size = batch.len() as u32;
        result.valid_count = valid_count;
        result.duplicate_count = duplicate_count;
        result.results = results;
        result.timestamp = Clock::get()?.unix_timestamp;
        result.status = BatchStatus::Completed;
        result.bump = ctx.bumps.result;

        emit!(BatchVerifyEvent {
            batch_size: batch.len() as u32,
            valid_count,
            duplicate_count,
            timestamp: result.timestamp,
        });

        Ok(())
    }

    pub fn query_result(ctx: Context<QueryResult>) -> Result<BatchResultView> {
        let r = &ctx.accounts.result;
        Ok(BatchResultView {
            batch_id: r.batch_id,
            valid_count: r.valid_count,
            duplicate_count: r.duplicate_count,
            results: r.results.clone(),
        })
    }
}

pub fn check_ed25519_data(
    ix: &Instruction,
    expected_pubkey: &[u8],
    expected_sig: &[u8],
    expected_msg: &[u8],
) -> Result<()> {
    require_keys_eq!(ix.program_id, ed25519_program::ID, ErrorCode::WrongPrecompileProgram);
    require!(ix.accounts.is_empty(), ErrorCode::PrecompileHasAccounts);

    let data = &ix.data;
    require!(data.len() >= 16, ErrorCode::PrecompileDataTooShort);
    require!(data[0] == 1, ErrorCode::BadSignatureCount);
    require!(data[1] == 0, ErrorCode::BadPadding);

    let sig_off  = u16::from_le_bytes([data[2],  data[3]])  as usize;
    let sig_ix   = u16::from_le_bytes([data[4],  data[5]]);
    let pk_off   = u16::from_le_bytes([data[6],  data[7]])  as usize;
    let pk_ix    = u16::from_le_bytes([data[8],  data[9]]);
    let msg_off  = u16::from_le_bytes([data[10], data[11]]) as usize;
    let msg_size = u16::from_le_bytes([data[12], data[13]]) as usize;
    let msg_ix   = u16::from_le_bytes([data[14], data[15]]);

    require!(
        sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX,
        ErrorCode::WrongInstructionIndex
    );

    let sig_end = sig_off.checked_add(64).ok_or(ErrorCode::OffsetOverflow)?;
    let pk_end  = pk_off.checked_add(32).ok_or(ErrorCode::OffsetOverflow)?;
    let msg_end = msg_off.checked_add(msg_size).ok_or(ErrorCode::OffsetOverflow)?;
    require!(
        sig_end <= data.len() && pk_end <= data.len() && msg_end <= data.len(),
        ErrorCode::OffsetOverflow
    );

    require!(msg_size == expected_msg.len(), ErrorCode::MessageMismatch);
    require!(&data[sig_off..sig_end] == expected_sig, ErrorCode::SignatureMismatch);
    require!(&data[pk_off..pk_end] == expected_pubkey, ErrorCode::PubkeyMismatch);
    require!(&data[msg_off..msg_end] == expected_msg, ErrorCode::MessageMismatch);

    Ok(())
}


#[derive(Accounts)]
pub struct VerifyBatch<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + BatchResult::MAX_SIZE,
        seeds = [b"result", payer.key().as_ref()],
        bump,
    )]
    pub result: Account<'info, BatchResult>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(address = ix_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct QueryResult<'info> {
    #[account(seeds = [b"result", payer.key().as_ref()], bump = result.bump)]
    pub result: Account<'info, BatchResult>,
    pub payer: Signer<'info>,
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
    pub bump: u8,
}

impl BatchResult {
    const MAX_SIZE: usize = 8 + 4 + 4 + 4 + 4 + (255 * 1) + 8 + 1 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct BatchResultView {
    pub batch_id: u64,
    pub valid_count: u32,
    pub duplicate_count: u32,
    pub results: Vec<bool>,
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
    #[msg("Preceding ix is not the Ed25519 program")]
    WrongPrecompileProgram,
    #[msg("Ed25519 ix must have no accounts")]
    PrecompileHasAccounts,
    #[msg("Ed25519 ix data too short")]
    PrecompileDataTooShort,
    #[msg("Ed25519 ix must verify exactly 1 signature")]
    BadSignatureCount,
    #[msg("Ed25519 ix padding byte must be zero")]
    BadPadding,
    #[msg("Ed25519 offsets must reference current ix")]
    WrongInstructionIndex,
    #[msg("Ed25519 offset out of bounds")]
    OffsetOverflow,
    #[msg("Signature bytes do not match precompile data")]
    SignatureMismatch,
    #[msg("Pubkey bytes do not match precompile data")]
    PubkeyMismatch,
    #[msg("Message bytes do not match precompile data")]
    MessageMismatch,
}
