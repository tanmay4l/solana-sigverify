use solana_client::rpc_client::RpcClient;
use solana_program::pubkey::Pubkey;
use std::str::FromStr;

fn main() {
    let client = RpcClient::new("http://localhost:8899".to_string());
    let program_id = Pubkey::from_str("2o1R3JBBaY39F6zRMyKpfZhFq88bEARA1b2bbUe39tVo").unwrap();

    println!("Batch Ed25519 Sig Verifier");

    if let Ok(acct) = client.get_account(&program_id) {
        if acct.executable {
            println!("Program: OK");
        }
    }

    if let Ok(slot) = client.get_slot() {
        println!("Validator: slot {}", slot);
    }
}
