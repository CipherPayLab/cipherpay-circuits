pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom"; // Num2Bits
include "../nullifier/nullifier.circom";    // NullifierFromCipherKey
// (NoteCommitment not strictly needed for nullifier-only audit, kept out to minimize constraints)

// ─────────────────────────────────────────────────────────────────────────────
// audit_withdraw_v1
//
// Proves: nullifier == Poseidon(cipherPayPubKey, randomness, tokenId)
// and binds memoHash == Poseidon(memo, 0) to support "purpose/invoice" claims.
//
// This is audit-only: does NOT require walletPrivKey, does NOT spend funds.
// Auditor anchors merkle_root_used / recipient / amount via on-chain WithdrawCompleted event.
// ─────────────────────────────────────────────────────────────────────────────
template AuditWithdrawV1() {
    // === Public inputs ===
    signal input nullifier;   // must match WithdrawCompleted.nullifier
    signal input amount;      // must match WithdrawCompleted.amount (event)
    signal input tokenId;     // field tokenId used in circuits (mint mapping off-chain)
    signal input memoHash;    // Poseidon(memo, 0)

    // === Private witness ===
    signal input cipherPayPubKey; // ownerCipherPayPubKey (opaque)
    signal input randomness;
    signal input memo;

    // Optional: constrain amount to u64
    component amtBits = Num2Bits(64);
    amtBits.in <== amount;

    // Nullifier binding (matches your NullifierFromCipherKey)
    component nul = NullifierFromCipherKey();
    nul.cipherPayPubKey <== cipherPayPubKey;
    nul.randomness      <== randomness;
    nul.tokenId         <== tokenId;

    nullifier === nul.nullifier;

    // Memo hash binding: Poseidon(memo, 0)
    component mh = Poseidon(2);
    mh.inputs[0] <== memo;
    mh.inputs[1] <== 0;
    memoHash === mh.out;
}

component main { public [nullifier, amount, tokenId, memoHash] } = AuditWithdrawV1();
