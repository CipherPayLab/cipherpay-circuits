pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";

/*
 * CipherPay Nullifier family
 *
 * Nullifier preimage mirrors the note-commitment preimage (see
 * note_commitment.circom), minus the cross-domain pkEncHash (the nullifier
 * does not need to bind the E2EE key -- it only needs to be a deterministic,
 * unlinkable spend tag of the note).
 *
 * Base:
 *   ownerCPPK = Poseidon(cipherPayPubKey, cipherPayPrivKey)
 *   nullifier = Poseidon(amount, ownerCPPK, randomness, tokenId, memo)
 *
 * Variants:
 *  - NullifierFromCipherKey():
 *      nullifier = Poseidon(amount, cipherPayPubKey, randomness, tokenId, memo)
 *
 *  - NullifierTagged(tag):
 *      ownerCPPK = Poseidon(cipherPayPubKey, cipherPayPrivKey)
 *      nullifier = Poseidon(tag, amount, ownerCPPK, randomness, tokenId, memo)
 *    (compile-time tag for domain separation; prevents cross-protocol reuse)
 *
 *  - NullifierFromCipherKeyTagged(tag):
 *      nullifier = Poseidon(tag, amount, cipherPayPubKey, randomness, tokenId, memo)
 *
 * Field order note:
 *  The order (amount, <ID>, randomness, tokenId, memo) matches the relative
 *  positions of the same fields inside NoteCommitment(), so that any off-chain
 *  tool that builds the nullifier preimage can reuse the commitment's field
 *  layout (derive ID_cp = Poseidon(cipherPayPubKey, cipherPayPrivKey) for
 *  Nullifier/NullifierTagged, or pass the pre-derived tag in
 *  NullifierFromCipherKey*, then drop pkEncHash).
 *
 * Notes:
 *  - Changing the nullifier formula (e.g., adding fields or a tag) is a
 *    BREAKING change for previously created notes. Do it at a clear version
 *    boundary, and keep off-chain nullifier derivation (SDK, relayer) in sync.
 */

// -----------------------------------------------------------------------------
// 1) Backward-compatible base component
// -----------------------------------------------------------------------------
template Nullifier() {
    // === Private inputs (mirror NoteCommitment preimage) ===
    signal input amount;                // same as in commitment
    // Raw wallet key pair (same operands as Poseidon for ID_cp in commitments)
    signal input cipherPayPubKey;
    signal input cipherPayPrivKey;
    signal input randomness;            // same as in commitment
    signal input tokenId;               // same as in commitment
    signal input memo;                  // same as in commitment

    // === Public output ===
    signal output nullifier;

    // ownerCPPK = Poseidon(pub, priv)
    component ID = Poseidon(2);
    ID.inputs[0] <== cipherPayPubKey;
    ID.inputs[1] <== cipherPayPrivKey;

    // nullifier = Poseidon(amount, ownerCPPK, randomness, tokenId, memo)
    component H = Poseidon(5);
    H.inputs[0] <== amount;
    H.inputs[1] <== ID.out;
    H.inputs[2] <== randomness;
    H.inputs[3] <== tokenId;
    H.inputs[4] <== memo;

    nullifier <== H.out;
}

// -----------------------------------------------------------------------------
// 2) If caller already computed cipherPayPubKey off-circuit/in a parent
// -----------------------------------------------------------------------------
template NullifierFromCipherKey() {
    // === Private inputs (mirror NoteCommitment preimage) ===
    signal input amount;
    signal input cipherPayPubKey;       // Poseidon(walletPubKey, walletPrivKey)
    signal input randomness;
    signal input tokenId;
    signal input memo;

    // === Public output ===
    signal output nullifier;

    // nullifier = Poseidon(amount, cipherPayPubKey, randomness, tokenId, memo)
    component H = Poseidon(5);
    H.inputs[0] <== amount;
    H.inputs[1] <== cipherPayPubKey;
    H.inputs[2] <== randomness;
    H.inputs[3] <== tokenId;
    H.inputs[4] <== memo;

    nullifier <== H.out;
}

// -----------------------------------------------------------------------------
// 3) Tagged (domain-separated) variants
//    Choose a small constant tag per circuit, e.g.:
//      1 = withdraw, 2 = transfer, 3 = deposit-refund, etc.
// -----------------------------------------------------------------------------
template NullifierTagged(tag) {
    // === Private inputs (mirror NoteCommitment preimage) ===
    signal input amount;
    signal input cipherPayPubKey;
    signal input cipherPayPrivKey;
    signal input randomness;
    signal input tokenId;
    signal input memo;

    // === Public output ===
    signal output nullifier;

    component ID = Poseidon(2);
    ID.inputs[0] <== cipherPayPubKey;
    ID.inputs[1] <== cipherPayPrivKey;

    // nullifier = Poseidon(tag, amount, ownerCPPK, randomness, tokenId, memo)
    component H = Poseidon(6);
    H.inputs[0] <== tag;         // compile-time constant
    H.inputs[1] <== amount;
    H.inputs[2] <== ID.out;
    H.inputs[3] <== randomness;
    H.inputs[4] <== tokenId;
    H.inputs[5] <== memo;

    nullifier <== H.out;
}

template NullifierFromCipherKeyTagged(tag) {
    // === Private inputs (mirror NoteCommitment preimage) ===
    signal input amount;
    signal input cipherPayPubKey;
    signal input randomness;
    signal input tokenId;
    signal input memo;

    // === Public output ===
    signal output nullifier;

    // nullifier = Poseidon(tag, amount, cipherPayPubKey, randomness, tokenId, memo)
    component H = Poseidon(6);
    H.inputs[0] <== tag;         // compile-time constant
    H.inputs[1] <== amount;
    H.inputs[2] <== cipherPayPubKey;
    H.inputs[3] <== randomness;
    H.inputs[4] <== tokenId;
    H.inputs[5] <== memo;

    nullifier <== H.out;
}
