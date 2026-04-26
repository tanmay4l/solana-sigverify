use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::instruction::Instruction;
use batch_sigverify::check_ed25519_data;

const PK: [u8; 32] = [9u8; 32];
const SIG: [u8; 64] = [7u8; 64];
const MSG: &[u8] = b"hello";

fn build_valid_ix() -> Instruction {
    let mut data = Vec::with_capacity(16 + 32 + 64 + MSG.len());
    let pk_off: u16 = 16;
    let sig_off: u16 = 16 + 32;
    let msg_off: u16 = 16 + 32 + 64;
    let msg_size: u16 = MSG.len() as u16;

    data.push(1);
    data.push(0);
    data.extend_from_slice(&sig_off.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&pk_off.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&msg_off.to_le_bytes());
    data.extend_from_slice(&msg_size.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&PK);
    data.extend_from_slice(&SIG);
    data.extend_from_slice(MSG);

    Instruction { program_id: ed25519_program::ID, accounts: vec![], data }
}

#[test]
fn happy_path() {
    let ix = build_valid_ix();
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_ok());
}

#[test]
fn wrong_program_rejected() {
    let mut ix = build_valid_ix();
    ix.program_id = anchor_lang::solana_program::system_program::ID;
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn non_max_index_rejected() {
    let mut ix = build_valid_ix();
    ix.data[4] = 0;
    ix.data[5] = 0;
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn signature_mismatch_rejected() {
    let mut ix = build_valid_ix();
    ix.data[16 + 32] ^= 0xFF;
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn pubkey_mismatch_rejected() {
    let mut ix = build_valid_ix();
    ix.data[16] ^= 0xFF;
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn message_mismatch_rejected() {
    let mut ix = build_valid_ix();
    let msg_start = 16 + 32 + 64;
    ix.data[msg_start] ^= 0xFF;
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn bad_count_rejected() {
    let mut ix = build_valid_ix();
    ix.data[0] = 2;
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn nonzero_padding_rejected() {
    let mut ix = build_valid_ix();
    ix.data[1] = 1;
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn accounts_present_rejected() {
    let mut ix = build_valid_ix();
    ix.accounts.push(anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
        anchor_lang::solana_program::system_program::ID,
        false,
    ));
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}

#[test]
fn truncated_data_rejected() {
    let mut ix = build_valid_ix();
    ix.data.truncate(10);
    assert!(check_ed25519_data(&ix, &PK, &SIG, MSG).is_err());
}
