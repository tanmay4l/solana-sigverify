# Solana Batch Ed25519 Signature Verifier

Lightweight Solana program for verifying batches of Ed25519 signatures with deduplication.


## Setup

```bash
anchor build
anchor test
```

## Usage

Deploy program:
```bash
solana-test-validator
anchor deploy
```

Verify batch:
```bash
cargo run --manifest-path client/Cargo.toml
```

## How it works

1. Submit batch of signatures + messages + public keys
2. Program deduplicates by comparing full 64-byte signatures
3. Verifies each unique signature via Ed25519 syscall
4. Stores results on-chain (batch_id, valid_count, duplicate_count)
5. Emits event with verification summary

## Performance

- Dedup cost: <1ms (negligible)
- Verify cost: ~600 CU per signature
- Save 600 CU per duplicate detected

## Program ID

```
2o1R3JBBaY39F6zRMyKpfZhFq88bEARA1b2bbUe39tVo
```
