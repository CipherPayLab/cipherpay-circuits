pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "../note_commitment/note_commitment.circom";
include "../merkle/merkle.circom";

// ─────────────────────────────────────────────────────────────────────────────
// CipherPay Deposit Circuit (append-only; verifies old root and computes new)
// Assumptions:
//  • Unused leaf at nextLeafIndex is 0 (empty-leaf convention).
//  • inPathElements/Indices are provided bottom→top.
//  • inPathIndices[i] = bit i of nextLeafIndex (LSB at level 0).
// ─────────────────────────────────────────────────────────────────────────────
template Deposit(depth) {
    // === Private inputs (note preimage) ===
    // Raw CipherPay key operands (k_pub, k_priv); hashed inside NoteCommitmentFromWallet.
    signal input ownerCipherPayPubKey;
    signal input ownerCipherPayPrivKey;
    signal input randomness;
    signal input tokenId;
    signal input memo;

    // Cross-domain binding: the owner's Curve25519 encryption public key
    // (32 bytes), split into two 128-bit LE limbs. The commitment will bind
    // Poseidon(ownerPkEncLo, ownerPkEncHi) so the ZK identity and E2EE
    // identity are fused into the same note.
    signal input ownerPkEncLo;
    signal input ownerPkEncHi;

    // === Merkle tree inputs ===
    signal input inPathElements[depth]; // sibling hashes bottom→top
    signal input inPathIndices[depth];  // 0 = (left=cur,right=sib), 1 = (left=sib,right=cur)
    signal input nextLeafIndex;         // index being inserted (private)

    // === Public inputs (binding & history) ===
    signal input nonce;                 // binds depositHash
    signal input amount;                // public amount (u64)
    signal input depositHash;           // Poseidon(derivedOwnerCipherPayPubKey, amount, nonce)
    signal input oldMerkleRoot;         // must equal the tree’s current root

    // === Public outputs ===
    signal output newCommitment;
    // Poseidon(ownerCipherPayPubKey, ownerCipherPayPrivKey); distinct name avoids clash with private inputs.
    signal output derivedOwnerCipherPayPubKey;
    signal output newMerkleRoot;
    signal output newNextLeafIndex;

    // -- Step 0: indices must match nextLeafIndex (and range-check it) ------
    component idxBits = Num2Bits(depth);
    idxBits.in <== nextLeafIndex;
    for (var i = 0; i < depth; i++) {
        inPathIndices[i] === idxBits.out[i];
    }

    // Optional: amount fits into 64 bits
    component amtBits = Num2Bits(64);
    amtBits.in <== amount;

    // -- Step 1: derive CipherPay identity + build commitment ----------------
    // pkEncHash = Poseidon(ownerPkEncLo, ownerPkEncHi) with 128-bit range checks
    component pkEnc = PoseidonPkEnc();
    pkEnc.pkEncLo <== ownerPkEncLo;
    pkEnc.pkEncHi <== ownerPkEncHi;

    // commitment = Poseidon(amount, derivedCipherPayPubKey, randomness,
    //                       tokenId, memo, pkEncHash)
    component note = NoteCommitmentFromWallet();
    note.amount        <== amount;
    note.cipherPayPubKey  <== ownerCipherPayPubKey;
    note.cipherPayPrivKey <== ownerCipherPayPrivKey;
    note.randomness    <== randomness;
    note.tokenId       <== tokenId;
    note.memo          <== memo;
    note.pkEncHash     <== pkEnc.pkEncHash;

    newCommitment               <== note.commitment;
    derivedOwnerCipherPayPubKey <== note.derivedCipherPayPubKey;

    // -- Step 2: enforce depositHash binding ---------------------------------
    component depHash = Poseidon(3);
    depHash.inputs[0] <== derivedOwnerCipherPayPubKey;
    depHash.inputs[1] <== amount;
    depHash.inputs[2] <== nonce;
    depositHash === depHash.out;

    // -- Step 3a: verify OLD merkle root for an empty leaf at nextLeafIndex --
    component mpOld = MerkleProof(depth);
    mpOld.leaf <== 0; // empty slot before insertion
    for (var i = 0; i < depth; i++) {
        mpOld.pathElements[i] <== inPathElements[i];
        mpOld.pathIndices[i]  <== inPathIndices[i];
    }
    oldMerkleRoot === mpOld.root;

    // -- Step 3b: compute NEW merkle root with the new commitment ------------
    component mpNew = MerkleProof(depth);
    mpNew.leaf <== newCommitment;
    for (var j = 0; j < depth; j++) {
        mpNew.pathElements[j] <== inPathElements[j];
        mpNew.pathIndices[j]  <== inPathIndices[j];
    }
    newMerkleRoot <== mpNew.root;

    // -- Step 4: next index (append semantics) --------------------------------
    newNextLeafIndex <== nextLeafIndex + 1;
}

// Public signals order (update your on-chain indices accordingly):
//
//  Outputs (declared order):
//   [0] newCommitment
//   [1] derivedOwnerCipherPayPubKey
//   [2] newMerkleRoot
//   [3] newNextLeafIndex
//
//  Public inputs (listed order in `public [...]`):
//   [4] amount
//   [5] depositHash
//   [6] oldMerkleRoot
//   [7] tokenId          ← NEW: on-chain contract verifies this against
//                                 the TokenMintRecord registry so the
//                                 committed tokenId matches the actual
//                                 SPL mint being deposited.
//
// Total public signals: 8
component main { public [amount, depositHash, oldMerkleRoot, tokenId] } = Deposit(16);