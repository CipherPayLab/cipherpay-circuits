// pragma circom 2.1.4;

pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom"; // Num2Bits
include "../note_commitment/note_commitment.circom";
include "../merkle/merkle.circom";

// ─────────────────────────────────────────────────────────────────────────────
// audit_payment_included_v1
//
// Combines:
//  (1) AuditPaymentV1: commitment opens to disclosed (amount, tokenId, memoHash)
//  (2) AuditMembershipV1: commitment included under merkleRoot
//
// Public inputs: [commitment, merkleRoot, amount, tokenId, memoHash]
// Private witness: [cipherPayPubKey, randomness, memo, merkle path]
// ─────────────────────────────────────────────────────────────────────────────
template AuditPaymentIncludedV1(depth) {
    // === Public inputs ===
    signal input commitment;
    signal input merkleRoot;
    signal input amount;
    signal input tokenId;
    signal input memoHash;

    // === Private witness ===
    signal input cipherPayPubKey;
    signal input randomness;
    signal input memo;

    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Optional: constrain amount to u64
    component amtBits = Num2Bits(64);
    amtBits.in <== amount;

    // Recompute commitment
    component note = NoteCommitment();
    note.amount          <== amount;
    note.cipherPayPubKey <== cipherPayPubKey;
    note.randomness      <== randomness;
    note.tokenId         <== tokenId;
    note.memo            <== memo;

    commitment === note.commitment;

    // Memo hash binding: Poseidon(memo, 0)
    component mh = Poseidon(2);
    mh.inputs[0] <== memo;
    mh.inputs[1] <== 0;
    memoHash === mh.out;

    // Merkle inclusion
    component mp = MerkleProof(depth);
    mp.leaf <== commitment;
    for (var i = 0; i < depth; i++) {
        mp.pathElements[i] <== pathElements[i];
        mp.pathIndices[i]  <== pathIndices[i];
    }
    merkleRoot === mp.root;
}

// Public: [commitment, merkleRoot, amount, tokenId, memoHash]
component main { public [commitment, merkleRoot, amount, tokenId, memoHash] } = AuditPaymentIncludedV1(16);
