# CipherPay Circuits

Zero-knowledge proof circuits for privacy-preserving payments with wallet-bound identities, encrypted note delivery, and Merkle tree integration.

Usage - refer to package.json

```bash
npm install
nvm use 18
npm run setup
npm run convert-vk-bin-to-anchor
npm run copy-vk-to-relayer
npm run copy-proof-artifacts-to-relayer-sdk-ui-zkaudit

npm run generate-example-proofs
npm run generate-bin-proofs

```

## Overview

CipherPay circuits implement privacy-preserving payment functionality using Circom 2.1.4 and the Groth16 proving system. The circuits provide shielded transfers with wallet-bound identities, encrypted note delivery, Merkle tree integration, and selective disclosure for compliance.

### Circuit Suite

CipherPay includes **5 specialized circuits**:

1. **Deposit** - Convert public funds to shielded notes
2. **Transfer** - Shielded transfers between users
3. **Withdraw** - Convert shielded notes to public funds
4. **Audit Payment** - Selective disclosure for payment compliance ⭐ NEW
5. **Audit Withdraw** - Selective disclosure for withdrawal compliance ⭐ NEW

### Key Features

- 🔒 **Privacy**: Hide transaction amounts, senders, and receivers
- 🔐 **Security**: Prevent double-spending with nullifiers
- 🌳 **Merkle Trees**: Efficient note inclusion proofs
- 📊 **Compliance**: Selective disclosure for auditing (audit circuits)
- ⚡ **Performance**: Optimized constraint counts
- 🔗 **Interoperable**: Solana and EVM support

## Audit Circuits

CipherPay includes specialized audit circuits that enable **selective disclosure** for compliance and regulatory requirements while preserving user privacy.

### Design Philosophy

Traditional privacy protocols face a dilemma: either provide complete anonymity (making compliance impossible) or reveal all transaction details (destroying privacy). CipherPay's audit circuits solve this by allowing users to selectively prove specific facts about their transactions without revealing sensitive information.

### Audit Payment Circuit

**Use Case**: Prove a payment occurred with a specific amount and purpose, without revealing payer identity.

**Example Scenario**:
```
Alice paid $1000 to a charity and needs to claim a tax deduction.
The auditor (IRS) needs to verify:
✓ Payment amount: $1000
✓ Payment purpose: "Charitable donation #12345"
✗ Payer identity: PRIVATE
✗ Full transaction history: PRIVATE
```

**How It Works**:
1. Alice generates an audit proof using `audit_payment.circom`
2. Public inputs: commitment, merkleRoot, amount=1000, tokenId, memoHash
3. Private inputs: cipherPayPubKey (identity), randomness, memo
4. The proof verifies:
   - The commitment opens to the disclosed amount
   - The commitment exists in the Merkle tree
   - The memo hash matches the invoice/purpose
5. Auditor can verify the proof without learning Alice's identity

### Audit Withdraw Circuit

**Use Case**: Prove a withdrawal occurred with specific details, without revealing user identity or providing spending authority.

**Example Scenario**:
```
Bob withdrew funds to pay a supplier and needs to prove it for accounting.
The auditor needs to verify:
✓ Withdrawal amount: $5000
✓ Withdrawal purpose: "Invoice #ABC123"
✓ Nullifier matches on-chain WithdrawCompleted event
✗ Withdrawer identity: PRIVATE
✗ Spending authority: NOT GRANTED
```

**How It Works**:
1. Bob generates an audit proof using `audit_withdraw.circom`
2. Public inputs: nullifier, amount=5000, tokenId, memoHash
3. Private inputs: cipherPayPubKey, randomness, memo
4. The proof verifies:
   - The nullifier matches the disclosed amount and purpose
   - The nullifier is linked to the on-chain event
5. Auditor can verify WITHOUT:
   - Learning Bob's identity
   - Getting Bob's walletPrivKey (no spending power)

### Audit Workflow

```
1. User performs transaction (deposit/transfer/withdraw)
   ↓
2. Transaction recorded on-chain with commitment/nullifier
   ↓
3. User stores private note details locally
   ↓
4. When audit needed:
   ↓
5. User generates audit proof with selective disclosure
   ↓
6. User shares proof + public inputs with auditor
   ↓
7. Auditor verifies proof on-chain or off-chain
   ↓
8. Auditor confirms compliance WITHOUT seeing private details
```

### Privacy Guarantees

**What Auditors CAN Verify**:
- ✅ Transaction amount
- ✅ Token type
- ✅ Transaction inclusion in Merkle tree
- ✅ Memo hash (for invoice/purpose matching)
- ✅ Link to on-chain events (via commitment/nullifier)

**What Auditors CANNOT Learn**:
- ❌ User identity (cipherPayPubKey)
- ❌ Note randomness
- ❌ Original memo content (only hash disclosed)
- ❌ Full transaction history
- ❌ Relationships between transactions

### Compliance Applications

1. **Tax Reporting**: Prove charitable donations, business expenses
2. **Regulatory Audits**: Demonstrate transaction legitimacy
3. **Forensic Investigation**: Prove specific transactions occurred
4. **Business Accounting**: Verify payroll, supplier payments
5. **Legal Discovery**: Selective disclosure for court proceedings

### Security Properties

- **Zero-Knowledge**: Only disclosed facts are revealed
- **Unforgeable**: Cannot fake proofs without private witness
- **Non-Interactive**: Proofs can be verified independently
- **Publicly Verifiable**: Anyone with verification key can check
- **Selective**: User controls what to disclose

## Core Circuits

### Transfer Circuit (`transfer.circom`)

**Purpose**: Shielded transfers between users with encrypted note delivery

- **Signals**: 19 total (18 private + 1 public)
- **Key Features**:
  - Amount conservation: `inAmount === out1Amount + out2Amount`
  - Token consistency: All notes use same token ID
  - Encrypted note delivery for recipient privacy
  - Merkle tree inclusion proof verification

### Deposit Circuit (`deposit.circom`)

**Purpose**: Convert public funds to shielded notes with Merkle tree integration

- **Signals**: 46 total (39 private + 3 public + 4 outputs)
- **Key Features**:
  - Privacy-enhanced deposit hash using `ownerCipherPayPubKey`
  - Unique nonce prevents hash collisions
  - Wallet-bound identity derivation
  - Merkle tree path verification and root update
  - Leaf index tracking for tree insertion

### Withdraw Circuit (`withdraw.circom`)

**Purpose**: Convert shielded notes to public funds with identity verification

- **Signals**: 9 total (5 private + 4 public)
- **Key Features**:
  - Merkle tree inclusion proof verification
  - Commitment reconstruction and validation
  - Wallet-bound identity verification

### Audit Payment Circuit (`audit_payment.circom`)

**Purpose**: Selective disclosure circuit for auditing payment commitments without revealing identity

- **Signals**: 5 public + 4 private (depth-dependent Merkle path)
- **Key Features**:
  - Proves commitment opens to disclosed `(amount, tokenId, memoHash)`
  - Verifies commitment inclusion in Merkle tree under specified root
  - Protects identity by keeping `cipherPayPubKey` private
  - Enables compliance verification without compromising privacy
  - Supports invoice/purpose auditing via memo hash binding

**Public Inputs**:
- `commitment` - The note commitment being audited
- `merkleRoot` - Merkle root at time of transaction
- `amount` - Transaction amount (disclosed)
- `tokenId` - Token type (disclosed)
- `memoHash` - Hash of memo for purpose verification

**Private Witness**:
- `cipherPayPubKey` - Owner identity (kept private)
- `randomness` - Note randomness (kept private)
- `memo` - Original memo (kept private, only hash disclosed)
- `pathElements[depth]` - Merkle proof path
- `pathIndices[depth]` - Merkle proof indices

### Audit Withdraw Circuit (`audit_withdraw.circom`)

**Purpose**: Selective disclosure circuit for auditing withdrawals without spending authority

- **Signals**: 4 public + 3 private
- **Key Features**:
  - Proves nullifier matches disclosed `(amount, tokenId, memoHash)`
  - Does NOT require `walletPrivKey` - audit-only, no spending power
  - Links nullifier to on-chain `WithdrawCompleted` event
  - Supports invoice/purpose verification via memo hash
  - Enables compliance without revealing note details or identity

**Public Inputs**:
- `nullifier` - Must match `WithdrawCompleted.nullifier` on-chain
- `amount` - Withdrawn amount (must match event)
- `tokenId` - Token type
- `memoHash` - Hash of memo for purpose verification

**Private Witness**:
- `cipherPayPubKey` - Owner identity (kept private)
- `randomness` - Note randomness (kept private)
- `memo` - Original memo (kept private, only hash disclosed)

**Use Case**: Auditors can verify a withdrawal's amount and purpose without:
- Gaining spending authority over the nullifier
- Learning the note owner's identity
- Accessing full transaction history

## Components

### Note Commitment Component (`note_commitment.circom`)

**Purpose**: Reusable component for computing note commitments

- **Signals**: 5 inputs, 1 output
- **Function**: `commitment = Poseidon(amount, cipherPayPubKey, randomness, tokenId, memo)`

### Nullifier Component (`nullifier.circom`)

**Purpose**: Reusable component for generating nullifiers

- **Signals**: 4 inputs, 1 output
- **Function**: `nullifier = Poseidon(ownerWalletPubKey, ownerWalletPrivKey, randomness, tokenId)`

## Cryptographic Primitives

### Identity Derivation

```javascript
cipherPayPubKey = Poseidon(walletPubKey, walletPrivKey);
```

### Note Commitment

```javascript
commitment = Poseidon(amount, cipherPayPubKey, randomness, tokenId, memo);
```

### Nullifier Generation

```javascript
nullifier = Poseidon(
  ownerWalletPubKey,
  ownerWalletPrivKey,
  randomness,
  tokenId
);
```

### Deposit Hash

```javascript
depositHash = Poseidon(ownerCipherPayPubKey, amount, nonce);
```

### Merkle Tree Operations

```javascript
// For deposit circuit
newMerkleRoot = computeMerkleRoot(newCommitment, inPathElements, inPathIndices);
newNextLeafIndex = nextLeafIndex + 1;
```

## Security Properties

### Privacy

- **Transaction Privacy**: Amounts, recipients, and sender relationships are hidden
- **Identity Privacy**: Wallet keys are never exposed on-chain
- **Note Privacy**: Note contents are encrypted for recipients

### Security

- **Double-Spending Prevention**: Nullifiers prevent note reuse
- **Merkle Tree Security**: Inclusion proofs verify note existence
- **Amount Conservation**: Mathematical constraints prevent value creation

### Auditability

- **Selective Disclosure**: Optional audit trails for compliance
- **Merkle Tree Verification**: Public verification of note inclusion
- **Nullifier Tracking**: Public tracking of spent notes
- **Audit Payment Circuit**: Prove transaction amount/purpose without revealing identity
- **Audit Withdraw Circuit**: Verify withdrawal details without spending authority
- **Compliance Ready**: Support for regulatory requirements via selective proofs

## Quick Start

### Prerequisites

- **Node.js** (v16 or later)
- **Circom** (v2.1.4)
- **snarkjs** (latest)

### Installation

```bash
# Clone repository
git clone <repository-url>
cd cipherpay-circuits

# Install dependencies
npm install

# Build circuits (includes ptau generation)
node scripts/setup.js

# Run tests
npm test
```

### Manual Ptau Setup (if needed)

```bash
# Create build directory
mkdir -p build

# Generate ptau files manually
cd build
npx snarkjs powersoftau new bn128 14 pot14_0000.ptau
npx snarkjs powersoftau prepare phase2 pot14_0000.ptau pot14_final.ptau
cd ..

# Build circuits
node scripts/setup.js
```

## Testing

### Test Suite

```bash
# Run all tests
npm test

# Run specific test file
npm test -- test/circuits.test.js

# Run with increased timeout for ZK proofs
npm test -- --testTimeout=30000
```

### Test Coverage

- ✅ **Circuit Structure**: Signal counts and types validation
- ✅ **Input Validation**: Correct input formats and constraints
- ✅ **Proof Generation**: ZK proof creation and verification
- ✅ **Error Handling**: Invalid input rejection
- ✅ **Build Verification**: Circuit file generation validation

### Expected Results

```
PASS  test/circuits.test.js
PASS  test/proof-generation.test.js

Test Suites: 2 passed, 2 total
Tests:       28 passed, 28 total
```

## Circuit Input Formats

### Transfer Circuit (19 signals)

```javascript
{
    // Private inputs (18 signals)
    inAmount: 100,
    inSenderWalletPubKey: 1234567890,
    inSenderWalletPrivKey: 1111111111,
    inRandomness: 9876543210,
    inTokenId: 1,
    inMemo: 0,
    inPathElements: Array(16).fill(0),
    inPathIndices: Array(16).fill(0),

    // Output note 1 (for recipient)
    out1Amount: 80,
    out1RecipientCipherPayPubKey: 2222222222,
    out1Randomness: 4444444444,
    out1TokenId: 1,
    out1Memo: 0,

    // Output note 2 (change note)
    out2Amount: 20,
    out2SenderCipherPayPubKey: 3333333333,
    out2Randomness: 5555555555,
    out2TokenId: 1,
    out2Memo: 0,

    // Public inputs (1 signal)
    encryptedNote: 12345678901234567890
}
```

### Deposit Circuit (46 signals)

```javascript
{
    // Private inputs (39 signals)
    ownerWalletPubKey: 1234567890,
    ownerWalletPrivKey: 1111111111,
    randomness: 9876543210,
    tokenId: 1,
    memo: 0,
    inPathElements: Array(16).fill(0), // Merkle path elements
    inPathIndices: Array(16).fill(0),  // Merkle path indices
    nextLeafIndex: 0,                   // Current next leaf index

    // Public inputs (3 signals)
    nonce: 3333333333,
    amount: 100,
    depositHash: 7777777777,

    // Public outputs (4 signals) - automatically generated
    // newCommitment: Shielded note commitment
    // ownerCipherPayPubKey: Derived CipherPay identity
    // newMerkleRoot: New merkle root after adding commitment
    // newNextLeafIndex: Next leaf index after insertion
}
```

### Withdraw Circuit (9 signals)

```javascript
{
    // Private inputs (5 signals)
    recipientWalletPrivKey: 1111111111,
    randomness: 9876543210,
    memo: 0,
    pathElements: Array(16).fill(0),
    pathIndices: Array(16).fill(0),

    // Public inputs (4 signals)
    recipientWalletPubKey: 1234567890,
    amount: 100,
    tokenId: 1,
    commitment: 7777777777
}
```

### Audit Payment Circuit (5 public + depth*2 private)

```javascript
{
    // Public inputs (5 signals)
    commitment: 7777777777,        // The note being audited
    merkleRoot: 8888888888,        // Merkle root at transaction time
    amount: 100,                   // Disclosed amount
    tokenId: 1,                    // Disclosed token type
    memoHash: 9999999999,          // Hash of memo (Poseidon(memo, 0))

    // Private inputs (4 + depth*2 signals)
    cipherPayPubKey: 2222222222,   // Owner identity (kept private)
    randomness: 9876543210,        // Note randomness (kept private)
    memo: 12345,                   // Original memo (kept private)
    pathElements: Array(16).fill(0), // Merkle path
    pathIndices: Array(16).fill(0)   // Path indices
}
```

**Note**: This circuit enables compliance audits. An auditor can verify:
- A payment of exactly 100 tokens occurred
- The payment is included in the Merkle tree
- The memo hash matches an invoice/purpose
- WITHOUT learning the payer's identity

### Audit Withdraw Circuit (4 public + 3 private)

```javascript
{
    // Public inputs (4 signals)
    nullifier: 3333333333,         // Must match WithdrawCompleted event
    amount: 100,                   // Disclosed amount
    tokenId: 1,                    // Token type
    memoHash: 9999999999,          // Hash of memo

    // Private inputs (3 signals)
    cipherPayPubKey: 2222222222,   // Owner identity (kept private)
    randomness: 9876543210,        // Note randomness (kept private)
    memo: 12345                    // Original memo (kept private)
}
```

**Note**: This circuit enables withdraw audits. An auditor can verify:
- A withdrawal of exactly 100 tokens occurred
- The nullifier matches the on-chain event
- The memo hash matches an invoice/purpose
- WITHOUT learning the withdrawer's identity
- WITHOUT gaining spending authority (no walletPrivKey required)

## Performance Characteristics

### Circuit Complexity

- **Transfer**: ~215 constraints
- **Deposit**: ~4,694 constraints (with Merkle tree)
- **Withdraw**: ~215 constraints
- **Audit Payment**: ~4,500 constraints (with Merkle tree, similar to deposit)
- **Audit Withdraw**: ~180 constraints (no Merkle tree, nullifier verification only)

### Proof Generation

- **Time**: 2-5 seconds per proof (depending on hardware)
- **Memory**: ~2GB RAM required
- **Proof Size**: ~2.5KB per proof

### Verification

- **Gas Cost**: ~200K gas per verification
- **Time**: <1 second per verification
- **On-chain**: Constant gas cost regardless of circuit complexity

## Build Process

### Power of Tau (Ptau) Files

Before building circuits, you need power of tau files for the Groth16 setup. These files are used to generate proving and verification keys.

#### Generating Ptau Files

```bash
# Create a new power of tau file (only needed once)
cd build
npx snarkjs powersoftau new bn128 14 pot14_0000.ptau

# Contribute to the ceremony (optional, for security)
npx snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="Your Name"

# Prepare phase 2 (required for each circuit)
npx snarkjs powersoftau prepare phase2 pot14_0001.ptau pot14_final.ptau
```

#### Using Existing Ptau Files

If you have existing ptau files, you can use them directly:

```bash
# Copy existing ptau files to build directory
cp /path/to/your/pot14_final.ptau build/pot14_final.ptau
```

#### Ptau File Requirements

- **Size**: Must be large enough for your circuit (14 for most circuits)
- **Curve**: Must use bn128 curve for compatibility
- **Phase**: Must be prepared for phase 2 (final.ptau)

#### Ptau File Management

```bash
# Check ptau file size
npx snarkjs powersoftau info pot14_final.ptau

# Verify ptau file integrity
npx snarkjs powersoftau verify pot14_final.ptau

# List available ptau files
ls -la build/*.ptau
```

#### Best Practices

- **Security**: Use trusted ptau files from public ceremonies
- **Size**: Choose ptau size based on circuit complexity (14 for most, 16+ for large circuits)
- **Storage**: Ptau files can be reused across multiple circuits
- **Backup**: Keep backups of your ptau files

### Generated Files

Each circuit generates:

- `{circuit}.r1cs` - R1CS constraint system
- `{circuit}_js/{circuit}.wasm` - WebAssembly circuit
- `{circuit}.zkey` - Proving key (Groth16)
- `verification_key.json` - Verification key
- `verifier-{circuit}.json` - Renamed verification key for tests

### Build Commands

```bash
# Build all circuits
node scripts/setup.js

# Generate zkey and verification key for specific circuit
node scripts/generate-zkey-vk.js deposit

# Generate proof for specific circuit
node scripts/generate-proof.js transfer
node scripts/generate-proof.js withdraw
node scripts/generate-proof.js deposit

# Convert verification keys to binary format for Solana
node scripts/convert-vk-to-binary.js

# Generate binary proof files for Solana testing
node scripts/generate-binary-proofs.js
```

### Setup Process Details

The `setup.js` script automatically handles ptau file generation if they don't exist:

1. **Compilation**: Circuits compiled to R1CS format
2. **Shared Ptau**: Creates single ptau file shared by all circuits
3. **Proving Keys**: Generates Groth16 proving keys using shared ptau file
4. **Verification Keys**: Exports verification keys for on-chain use
5. **File Distribution**: Copies keys to expected locations

## Solana Integration

### Binary Format Conversion

The circuits support Solana on-chain verification through binary format conversion:

```bash
# Convert JSON verification keys to binary
node scripts/convert-vk-to-binary.js

# Generate binary proof files for testing
node scripts/generate-binary-proofs.js
```

### Generated Binary Files

- `{circuit}_vk.bin` - Binary verification key for groth16-solana
- `deposit_proof.bin` - Binary proof (512 bytes)
- `deposit_public_inputs.bin` - Binary public signals (128 bytes)

## Troubleshooting

### Common Issues

1. **"circom not found"**

   ```bash
   npm install -g circom
   ```

2. **"snarkjs not found"**

   ```bash
   npm install -g snarkjs
   ```

3. **"WASM file not found"**

   ```bash
   node scripts/setup.js
   ```

4. **"Test timeout"**

   ```bash
   npm test -- --testTimeout=30000
   ```

5. **"Memory issues"**

   ```bash
   node --max-old-space-size=4096 scripts/setup.js
   ```

6. **"InvalidZkProof" in Solana tests**

   ```bash
   # Regenerate verification keys
   node scripts/setup.js
   node scripts/convert-vk-to-binary.js
   # Rebuild anchor program
   anchor build -- --features real-crypto
   ```

7. **"ptau file not found" or "Invalid ptau file"**

   ```bash
   # Regenerate ptau files
   cd build
   npx snarkjs powersoftau new bn128 14 pot14_0000.ptau
   npx snarkjs powersoftau prepare phase2 pot14_0000.ptau pot14_final.ptau
   # Rebuild circuits
   cd .. && node scripts/setup.js
   ```

8. **"ptau file too small"**
   ```bash
   # Use larger ptau file (increase size from 14 to 16 or higher)
   npx snarkjs powersoftau new bn128 16 pot16_0000.ptau
   npx snarkjs powersoftau prepare phase2 pot16_0000.ptau pot16_final.ptau
   ```

## Documentation

For detailed documentation, see the `/docs` directory:

- **[Technical Specification](docs/technical-spec.md)** - Complete circuit specifications
- **[Circuit Implementation Guide](docs/circuit-implementation.md)** - Development workflow
- **[Developer Guide](docs/developer-guide.md)** - Getting started guide

## Project Structure

```
cipherpay-circuits/
├── circuits/                    # Circuit implementations
│   ├── transfer/
│   ├── deposit/
│   ├── withdraw/
│   ├── audit_payment/           # NEW: Audit payment circuit
│   ├── audit_withdraw/          # NEW: Audit withdraw circuit
│   ├── note_commitment/
│   ├── nullifier/
│   └── merkle/
├── test/                       # Test files
│   ├── helpers.js
│   ├── circuits.test.js
│   └── proof-generation.test.js
├── scripts/                    # Build scripts
│   ├── setup.js
│   ├── generate-zkey-vk.js
│   ├── generate-proof.js
│   ├── verify-proof.js
│   ├── convert-vk-to-binary.js
│   ├── generate-binary-proofs.js
│   └── README.md
├── build/                      # Build outputs
├── docs/                       # Documentation
└── package.json
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
