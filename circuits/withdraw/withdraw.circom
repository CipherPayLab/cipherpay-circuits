pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "../merkle/merkle.circom";
include "../nullifier/nullifier.circom";
include "../note_commitment/note_commitment.circom";

// CipherPay Withdraw Circuit (parameterized Merkle depth)
//
// Key-domain separation (per whitepaper Appendix A):
//   - CipherPay identity keys (cipherPayPubKey, cipherPayPrivKey) are PRIVATE.
//     They are used ONLY to prove ownership of the note being spent and to
//     derive the nullifier. They MUST NOT appear in public signals; otherwise
//     withdrawals would be trivially linkable back to the sender's shielded
//     identity across transactions.
//
//   - The Solana payout address (recipient_owner) is PUBLIC. It is the
//     account that receives the unwrapped SPL tokens and is chosen freely by
//     the prover at withdraw time. It is exposed as two 128-bit LE limbs
//     (recipientOwner_lo, recipientOwner_hi) so the on-chain verifier can
//     reconstruct the 32-byte Pubkey and bind it to the `recipient_owner`
//     account passed by the transaction.
//
// Public signals order (outputs first, then public inputs):
//   [ nullifier, merkleRoot, recipientOwner_lo, recipientOwner_hi, amount, tokenId ]
template Withdraw(depth) {
    // === Private inputs ===
    // CipherPay identity keys (spend / nullifier authority).
    // cipherPayPubKey  is Poseidon-derived pub key used inside the commitment;
    // cipherPayPrivKey authorizes this spend via the Poseidon(pub, priv) tag.
    signal input cipherPayPubKey;
    signal input cipherPayPrivKey;

    signal input randomness;                  // note randomness
    signal input memo;                        // optional memo
    signal input pathElements[depth];         // Merkle auth path (bottom -> top)
    signal input pathIndices[depth];          // 0 => (left=cur,right=sib), 1 => (left=sib,right=cur)
    signal input commitment;                  // expected note commitment (private)

    // Spender's own Curve25519 encryption pubkey limbs, required to
    // reconstruct the commitment under the new cross-domain binding
    // (see Whitepaper Appendix A.6). These remain PRIVATE -- they are
    // the spender's identity and would otherwise enable transaction
    // linkage across withdraws.
    signal input pkEncLo;
    signal input pkEncHi;

    // === Public inputs ===
    //
    // Solana recipient owner pubkey (32 bytes) split into two 128-bit LE limbs:
    //   - recipientOwner_lo: LE integer of bytes[ 0..16)
    //   - recipientOwner_hi: LE integer of bytes[16..32)
    //
    // These are *not* used in arithmetic; they are exposed so the on-chain
    // program can reconstruct the 32-byte Pubkey and compare to recipient_owner.
    // The range checks below are REQUIRED for soundness: without them a prover
    // could stuff bits >= 2^128 into either limb, and the on-chain
    // `pubkey_from_limbs` (which takes only the low 16 bytes of each 32B
    // field-element encoding) would silently truncate them, breaking the
    // public-input binding.
    signal input recipientOwner_lo;           // low 128 bits (LE)
    signal input recipientOwner_hi;           // high 128 bits (LE)

    signal input amount;                      // note amount
    signal input tokenId;                     // note token id

    // === Public outputs ===
    signal output nullifier;                  // spend nullifier (prevents reuse)
    signal output merkleRoot;                 // Merkle root of the tree

    // -- Range-check payout-address limbs to fit in 128 bits each --
    component ownerLoBits = Num2Bits(128);
    component ownerHiBits = Num2Bits(128);
    ownerLoBits.in <== recipientOwner_lo;
    ownerHiBits.in <== recipientOwner_hi;

    // -- Step 1: derive CipherPay identity tag + recompute commitment from preimage --
    // Raw CipherPay key operands k_pub / k_priv feed NoteCommitmentFromWallet's
    // cipherPayPubKey / cipherPayPrivKey ports (derivedCipherPayPubKey = Poseidon pair).
    component pkEnc = PoseidonPkEnc();
    pkEnc.pkEncLo <== pkEncLo;
    pkEnc.pkEncHi <== pkEncHi;

    component note = NoteCommitmentFromWallet();
    note.amount        <== amount;
    note.cipherPayPubKey  <== cipherPayPubKey;
    note.cipherPayPrivKey <== cipherPayPrivKey;
    note.randomness    <== randomness;
    note.tokenId       <== tokenId;
    note.memo          <== memo;
    note.pkEncHash     <== pkEnc.pkEncHash;

    // Provided private `commitment` must match reconstructed one
    note.commitment === commitment;

    // -- Step 2: Merkle inclusion proof (commitment in tree) --
    component mp = MerkleProof(depth);
    mp.leaf <== commitment;
    for (var i = 0; i < depth; i++) {
        mp.pathElements[i] <== pathElements[i];
        mp.pathIndices[i]  <== pathIndices[i];   // boolean enforced inside MerkleProof
    }
    merkleRoot <== mp.root;

    // -- Step 3: derive nullifier (prevents double-spend) --
    // Preimage mirrors the note commitment (minus pkEncHash): the nullifier
    // now binds the full note tuple so it cannot be replayed across notes
    // that share an (identity, randomness, tokenId) but differ in amount/memo.
    component nul = NullifierFromCipherKey();
    nul.amount          <== amount;
    nul.cipherPayPubKey <== note.derivedCipherPayPubKey; // Poseidon(pub, priv)
    nul.randomness      <== randomness;
    nul.tokenId         <== tokenId;
    nul.memo            <== memo;
    nullifier           <== nul.nullifier;
}

// Outputs first, then declared `public` inputs become public signals in this order:
// [ nullifier, merkleRoot, recipientOwner_lo, recipientOwner_hi, amount, tokenId ]
component main { public [recipientOwner_lo, recipientOwner_hi, amount, tokenId] } = Withdraw(16);
