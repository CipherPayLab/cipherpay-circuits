const crypto = require('crypto');

// Helper function to generate a simple Merkle tree for testing
function generateSimpleMerkleTree(depth = 16) {
    const pathElements = Array(depth).fill(0);
    const pathIndices = Array(depth).fill(0);
    
    return {
        pathElements: pathElements,
        pathIndices: pathIndices,
        root: 0 // Simplified for testing
    };
}

// Helper function to derive CipherPay pubkey from wallet keys (simplified for testing)
function deriveCipherPayPubKey(walletPubKey, walletPrivKey) {
    // Simplified derivation - in real implementation this would use Poseidon hash
    return walletPubKey + walletPrivKey;
}

// Helper function to compute note commitment (simplified for testing)
function computeNoteCommitment(amount, cipherPayPubKey, randomness, tokenId, memo) {
    // Simplified commitment - in real implementation this would use Poseidon hash
    return amount + cipherPayPubKey + randomness + tokenId + memo;
}

// Helper function to compute deposit hash (simplified for testing)
function computeDepositHash(ownerCipherPayPubKey, amount, nonce) {
    // Simplified hash - in real implementation this would use Poseidon hash
    return ownerCipherPayPubKey + amount + nonce;
}

// Generate valid transfer input structure
function generateTransferInput() {
    const merkleData = generateSimpleMerkleTree(16);
    
    // Generate wallet keys
    const inSenderCipherPayPubKey = 1234567890;
    const inSenderCipherPayPrivKey = 1111111111;
    
    // Generate output keys
    const out1RecipientCipherPayPubKey = 2222222222;
    const out2SenderCipherPayPubKey = 3333333333;
    
    return {
        // Private inputs for input note
        inAmount: 100,
        inSenderCipherPayPubKey: inSenderCipherPayPubKey,
        inSenderCipherPayPrivKey: inSenderCipherPayPrivKey,
        inRandomness: 9876543210,
        inTokenId: 1,
        inMemo: 0,
        inPathElements: merkleData.pathElements,
        inPathIndices: merkleData.pathIndices,

        // Private inputs for output notes
        out1Amount: 80,
        out1RecipientCipherPayPubKey: out1RecipientCipherPayPubKey,
        out1Randomness: 4444444444,
        out1TokenId: 1,
        out1Memo: 0,
        out2Amount: 20,
        out2SenderCipherPayPubKey: out2SenderCipherPayPubKey,
        out2Randomness: 5555555555,
        out2TokenId: 1,
        out2Memo: 0,

        // Public inputs (encrypted note for recipient)
        encryptedNote: 12345678901234567890 // BigInt representation of encrypted note
    };
}

// Generate valid deposit input structure
function generateDepositInput() {
    const ownerCipherPayPubKey = 1234567890;
    const ownerCipherPayPrivKey = 1111111111;
    const derivedOwnerCipherPayPubKey = deriveCipherPayPubKey(ownerCipherPayPubKey, ownerCipherPayPrivKey);
    const amount = 100;
    const nonce = 3333333333;
    const depositHash = computeDepositHash(derivedOwnerCipherPayPubKey, amount, nonce);
    
    return {
        // Private inputs
        ownerCipherPayPubKey: ownerCipherPayPubKey,
        ownerCipherPayPrivKey: ownerCipherPayPrivKey,
        randomness: 9876543210,
        tokenId: 1,
        memo: 0,

        // Public inputs
        nonce: nonce,
        amount: amount,
        depositHash: depositHash
    };
}

// Generate valid withdraw input structure
function generateWithdrawInput() {
    const merkleData = generateSimpleMerkleTree(16);
    const recipientWalletPubKey = 1234567890;
    const recipientWalletPrivKey = 1111111111;
    const recipientCipherPayPubKey = deriveCipherPayPubKey(recipientWalletPubKey, recipientWalletPrivKey);
    const amount = 100;
    const tokenId = 1;
    const commitment = computeNoteCommitment(amount, recipientCipherPayPubKey, 9876543210, tokenId, 0);
    
    return {
        // Private inputs
        recipientWalletPrivKey: recipientWalletPrivKey,
        randomness: 9876543210,
        memo: 0,
        pathElements: merkleData.pathElements,
        pathIndices: merkleData.pathIndices,

        // Public inputs
        recipientWalletPubKey: recipientWalletPubKey,
        amount: amount,
        tokenId: tokenId,
        commitment: commitment
    };
}

// Generate valid note commitment input structure
function generateNoteCommitmentInput() {
    return {
        amount: 100,
        cipherPayPubKey: 1234567890,
        randomness: 9876543210,
        tokenId: 1,
        memo: 0
    };
}

// Generate valid nullifier input structure (matches Nullifier() template inputs)
function generateNullifierInput() {
    return {
        amount: 100,
        cipherPayPubKey: 1234567890,
        cipherPayPrivKey: 1111111111,
        randomness: 9876543210,
        tokenId: 1,
        memo: 0
    };
}

module.exports = {
    generateSimpleMerkleTree,
    deriveCipherPayPubKey,
    computeNoteCommitment,
    computeDepositHash,
    generateTransferInput,
    generateDepositInput,
    generateWithdrawInput,
    generateNoteCommitmentInput,
    generateNullifierInput
}; 