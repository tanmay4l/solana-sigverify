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

1. Client sends Ed25519 precompile instructions before `verify_batch`
2. Runtime verifies signatures at transaction sanitization (free)
3. Program deduplicates by comparing full 64-byte signatures
4. Validates each precompile instruction via the Instructions sysvar
5. Stores results on-chain (batch_id, valid_count, duplicate_count)

## Performance

- Signature verification: done by runtime, not the program
- Program overhead: ~3–5K CU per batch (mostly PDA init)
- Save one precompile ix per duplicate detected

## Program ID

```
2o1R3JBBaY39F6zRMyKpfZhFq88bEARA1b2bbUe39tVo
```
