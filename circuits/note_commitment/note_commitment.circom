pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

/*
 * CipherPay Note Commitment family
 *
 * NEW cross-domain binding (see Whitepaper Appendix A.6 / A.7.6):
 *   The commitment now includes a hash of the recipient's Curve25519
 *   encryption public key `pk_enc`, so a single note binds BOTH key
 *   systems (ZK identity in BN254 and X25519 E2EE).
 *
 *   pkEncHash := Poseidon(pkEncLo, pkEncHi)
 *     where pkEncLo = LE integer of pk_enc[ 0..16)   (128-bit range-checked)
 *           pkEncHi = LE integer of pk_enc[16..32)   (128-bit range-checked)
 *
 *   commitment = Poseidon(amount, cipherPayPubKey, randomness,
 *                         tokenId, memo, pkEncHash)
 *
 * Variants:
 *  - NoteCommitment(): base, takes pkEncHash directly.
 *  - NoteCommitmentTagged(tag): prepends a compile-time domain tag.
 *  - NoteCommitmentFromWallet(): derives derivedCipherPayPubKey from raw
 *    CipherPay key operands (cipherPayPubKey, cipherPayPrivKey); still takes
 *    pkEncHash directly.
 *
 * Helper:
 *  - PoseidonPkEnc(): takes the two 128-bit limbs of pk_enc, enforces
 *    range, and emits pkEncHash. Call this from each top-level circuit
 *    so every caller performs the same canonical encoding.
 */

// -----------------------------------------------------------------------------
// 0) Limb hasher for pk_enc (32-byte Curve25519 key -> field element)
// -----------------------------------------------------------------------------
//
// Why limbs? pk_enc is 256 bits, which does not fit in a single BN254 scalar.
// We split into two 128-bit halves so each fits comfortably, and enforce
// canonical encoding via Num2Bits(128). Without the range check a prover
// could pick non-canonical limb values that happen to sit in the BN254 field
// but whose byte serialization differs from the intended 32-byte key,
// breaking the binding to the X25519 pubkey actually used for encryption.
template PoseidonPkEnc() {
    signal input  pkEncLo;
    signal input  pkEncHi;
    signal output pkEncHash;

    component loBits = Num2Bits(128);
    component hiBits = Num2Bits(128);
    loBits.in <== pkEncLo;
    hiBits.in <== pkEncHi;

    component H = Poseidon(2);
    H.inputs[0] <== pkEncLo;
    H.inputs[1] <== pkEncHi;
    pkEncHash   <== H.out;
}

// -----------------------------------------------------------------------------
// 1) Base commitment component (now 6-input Poseidon)
// -----------------------------------------------------------------------------
template NoteCommitment() {
    // === Private inputs ===
    signal input amount;            // token amount
    signal input cipherPayPubKey;   // identity tag ID_cp (\texttt{Poseidon} of raw keys)
    signal input randomness;        // note randomness
    signal input tokenId;           // token type id
    signal input memo;              // optional memo
    signal input pkEncHash;         // Poseidon(pkEncLo, pkEncHi)  -- see PoseidonPkEnc

    // === Public output ===
    signal output commitment;

    // commitment = Poseidon(amount, cipherPayPubKey, randomness, tokenId, memo, pkEncHash)
    component H = Poseidon(6);
    H.inputs[0] <== amount;
    H.inputs[1] <== cipherPayPubKey;
    H.inputs[2] <== randomness;
    H.inputs[3] <== tokenId;
    H.inputs[4] <== memo;
    H.inputs[5] <== pkEncHash;

    commitment <== H.out;
}

// -----------------------------------------------------------------------------
// 2) Tagged variant (domain separation)
//    Use a small constant tag (e.g., 1 for deposit notes, 2 for transfer outputs, etc.)
// -----------------------------------------------------------------------------
template NoteCommitmentTagged(tag) {
    // === Private inputs ===
    signal input amount;
    signal input cipherPayPubKey;
    signal input randomness;
    signal input tokenId;
    signal input memo;
    signal input pkEncHash;

    // === Public output ===
    signal output commitment;

    // commitment = Poseidon(tag, amount, cipherPayPubKey, randomness, tokenId, memo, pkEncHash)
    component H = Poseidon(7);
    H.inputs[0] <== tag;            // template parameter (constant at compile time)
    H.inputs[1] <== amount;
    H.inputs[2] <== cipherPayPubKey;
    H.inputs[3] <== randomness;
    H.inputs[4] <== tokenId;
    H.inputs[5] <== memo;
    H.inputs[6] <== pkEncHash;

    commitment <== H.out;
}

// -----------------------------------------------------------------------------
// 3) Convenience variant: derive derivedCipherPayPubKey from raw CipherPay keys
//    (k_pub, k_priv operands to Poseidon). Useful when the caller has
//    those keys and wants fewer moving parts.
//    Caller still supplies pkEncHash (use PoseidonPkEnc on limbs upstream).
// -----------------------------------------------------------------------------
template NoteCommitmentFromWallet() {
    // === Private inputs ===
    // Raw CipherPay key operands (k_pub, k_priv). Not the pre-derived identity
    // tag used in NoteCommitment(); here ID = Poseidon(k_pub, k_priv) internally.
    signal input amount;
    signal input cipherPayPubKey;
    signal input cipherPayPrivKey;
    signal input randomness;
    signal input tokenId;
    signal input memo;
    signal input pkEncHash;

    // === Public outputs ===
    signal output commitment;
    signal output derivedCipherPayPubKey;

    // derivedCipherPayPubKey = Poseidon(cipherPayPubKey, cipherPayPrivKey)
    component ID = Poseidon(2);
    ID.inputs[0] <== cipherPayPubKey;
    ID.inputs[1] <== cipherPayPrivKey;
    derivedCipherPayPubKey <== ID.out;

    // commitment = Poseidon(amount, derivedCipherPayPubKey, randomness, tokenId, memo, pkEncHash)
    component H = Poseidon(6);
    H.inputs[0] <== amount;
    H.inputs[1] <== derivedCipherPayPubKey;
    H.inputs[2] <== randomness;
    H.inputs[3] <== tokenId;
    H.inputs[4] <== memo;
    H.inputs[5] <== pkEncHash;

    commitment <== H.out;
}
