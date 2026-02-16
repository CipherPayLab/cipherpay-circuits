# Audit Circuits Documentation

Documentation for CipherPay's audit circuits: `audit_payment.circom` and `audit_withdraw.circom`.

## Overview

The audit circuits enable **selective disclosure** for compliance and regulatory requirements while preserving user privacy. They allow users to prove specific facts about their transactions without revealing sensitive information.

## Circuit Comparison

| Feature | audit_payment | audit_withdraw |
|---------|--------------|----------------|
| **Purpose** | Prove payment details | Prove withdrawal details |
| **Public Inputs** | 5 signals | 4 signals |
| **Private Inputs** | 4 + depth*2 signals | 3 signals |
| **Constraints** | ~4,500 (with Merkle) | ~180 (no Merkle) |
| **Merkle Proof** | ✅ Required | ❌ Not required |
| **Spending Authority** | N/A | ❌ Not granted |
| **Identity Protection** | ✅ Full | ✅ Full |

---

## Audit Payment Circuit

**File**: `circuits/audit_payment/audit_payment.circom`

### Purpose

Enable selective disclosure of payment commitment details for compliance auditing without revealing user identity.

### Public Inputs (5 signals)

```javascript
{
    commitment: BigInt,    // The note commitment being audited
    merkleRoot: BigInt,    // Merkle root at transaction time
    amount: BigInt,        // Disclosed transaction amount
    tokenId: BigInt,       // Disclosed token type
    memoHash: BigInt       // Hash of memo (Poseidon(memo, 0))
}
```

### Private Witness (4 + depth*2 signals)

```javascript
{
    cipherPayPubKey: BigInt,           // Owner identity (PRIVATE)
    randomness: BigInt,                // Note randomness (PRIVATE)
    memo: BigInt,                      // Original memo (PRIVATE)
    pathElements: BigInt[depth],       // Merkle path elements
    pathIndices: BigInt[depth]         // Merkle path indices
}
```

### What It Proves

1. **Commitment Opens to Disclosed Values**: The commitment can be reconstructed using the disclosed `amount`, `tokenId`, `memoHash`, and private witness
2. **Merkle Inclusion**: The commitment exists in the Merkle tree under the disclosed `merkleRoot`
3. **Memo Hash Correctness**: `memoHash = Poseidon(memo, 0)`

### What It Protects

- ✅ User identity (`cipherPayPubKey` remains private)
- ✅ Note randomness (cannot be used to link transactions)
- ✅ Original memo content (only hash is disclosed)

### Use Cases

1. **Tax Reporting**
   - Prove charitable donation amount
   - Verify business expense
   - Claim tax deductions

2. **Regulatory Audits**
   - Demonstrate transaction legitimacy
   - Prove compliance with spending limits
   - Verify transaction occurred

3. **Legal Discovery**
   - Selective disclosure for court proceedings
   - Prove specific payments without revealing others

4. **Business Accounting**
   - Verify invoice payments
   - Audit expense reports
   - Confirm budget compliance

### Example Scenario

```
Alice paid $1000 to a charity and needs a tax deduction.

Alice generates audit proof:
- Public: commitment, merkleRoot, amount=1000, tokenId=USDC, memoHash
- Private: cipherPayPubKey, randomness, memo="Charity ABC"

Auditor (IRS) verifies:
✓ Payment of $1000 occurred
✓ Payment is in the Merkle tree
✓ Memo hash matches invoice
✗ Cannot learn Alice's identity
✗ Cannot see other transactions
✗ Cannot spend or track Alice's funds
```

---

## Audit Withdraw Circuit

**File**: `circuits/audit_withdraw/audit_withdraw.circom`

### Purpose

Enable selective disclosure of withdrawal details for compliance auditing **without granting spending authority**.

### Public Inputs (4 signals)

```javascript
{
    nullifier: BigInt,     // Must match WithdrawCompleted.nullifier on-chain
    amount: BigInt,        // Disclosed withdrawal amount
    tokenId: BigInt,       // Token type
    memoHash: BigInt       // Hash of memo for purpose verification
}
```

### Private Witness (3 signals)

```javascript
{
    cipherPayPubKey: BigInt,    // Owner identity (PRIVATE)
    randomness: BigInt,         // Note randomness (PRIVATE)
    memo: BigInt                // Original memo (PRIVATE)
}
```

### What It Proves

1. **Nullifier Correctness**: `nullifier = Poseidon(cipherPayPubKey, randomness, tokenId)`
2. **Amount Disclosure**: The withdrawal was for the disclosed amount
3. **Memo Hash Correctness**: `memoHash = Poseidon(memo, 0)`
4. **On-Chain Link**: Nullifier matches the on-chain `WithdrawCompleted` event

### What It Protects

- ✅ User identity (`cipherPayPubKey` remains private)
- ✅ Spending authority (NO `walletPrivKey` required or disclosed)
- ✅ Note randomness (cannot link to other transactions)
- ✅ Original memo content (only hash disclosed)

### Key Security Feature

**NO walletPrivKey Required**: Unlike the regular withdraw circuit, the audit circuit does NOT require the user's `walletPrivKey`. This means:

- Auditor can verify withdrawal occurred
- Auditor CANNOT spend the nullifier
- Auditor CANNOT impersonate the user
- Auditor CANNOT perform withdrawals

### Use Cases

1. **Supplier Payment Verification**
   - Prove payment to vendor
   - Verify invoice satisfaction
   - Audit accounts payable

2. **Payroll Audits**
   - Confirm salary payments
   - Verify contractor payments
   - Audit compensation compliance

3. **Forensic Investigations**
   - Prove specific withdrawals
   - Track fund movements (with user cooperation)
   - Demonstrate transaction occurrence

4. **Regulatory Reporting**
   - AML/KYC compliance
   - Large transaction reporting
   - Suspicious activity investigation

### Example Scenario

```
Bob withdrew $5000 to pay a supplier and needs to prove it for accounting.

Bob generates audit proof:
- Public: nullifier, amount=5000, tokenId=USDC, memoHash
- Private: cipherPayPubKey, randomness, memo="Invoice #ABC123"

Auditor verifies:
✓ Withdrawal of $5000 occurred
✓ Nullifier matches on-chain WithdrawCompleted event
✓ Memo hash matches supplier invoice
✗ Cannot learn Bob's identity
✗ Cannot gain spending authority
✗ Cannot see Bob's other transactions
```

---

## Comparison with Regular Circuits

### vs. Regular Transfer Circuit

| Feature | transfer.circom | audit_payment.circom |
|---------|----------------|---------------------|
| **Purpose** | Perform transfer | Prove transfer occurred |
| **Spending** | ✅ Spends note | ❌ No spending |
| **Identity** | Private | Private |
| **Amount** | Private | **Public** (disclosed) |
| **Merkle Proof** | Required | Required |
| **Creates New Notes** | ✅ Yes (2 outputs) | ❌ No |

### vs. Regular Withdraw Circuit

| Feature | withdraw.circom | audit_withdraw.circom |
|---------|----------------|----------------------|
| **Purpose** | Perform withdrawal | Prove withdrawal occurred |
| **walletPrivKey** | **Required** | ❌ **Not required** |
| **Spending Authority** | ✅ Granted | ❌ Not granted |
| **Identity** | Private | Private |
| **Amount** | Public | Public |
| **Merkle Proof** | Required | ❌ Not required |
| **Nullifier** | Spends | Verifies only |

---

## Building and Testing

### Build Audit Circuits

```bash
# Build all circuits including audit circuits
npm run setup

# Build specific audit circuit
node scripts/setup.js audit_payment
node scripts/setup.js audit_withdraw
```

### Generate Example Proofs

```bash
# Generate audit payment proof
node scripts/generate-example-proof.js audit_payment

# Generate audit withdraw proof
node scripts/generate-example-proof.js audit_withdraw
```

### Convert to Binary (for Solana)

```bash
# Convert verification keys to binary
node scripts/convert-vk-to-bin.js --circuit audit_payment
node scripts/convert-vk-to-bin.js --circuit audit_withdraw

# Generate binary proofs for testing
node scripts/generate-binary-proofs.js
```

---

## Integration Guide

### For Application Developers

#### Generate Audit Payment Proof

```javascript
import { CipherPaySDK } from 'cipherpay-sdk';

// User wants to prove they paid $1000 for charity
const auditProof = await sdk.generateAuditPaymentProof({
  commitment: noteCommitment,
  merkleRoot: rootAtTransactionTime,
  amount: 1000n,
  tokenId: 1n,
  memo: "Charitable donation #12345",
  
  // Private witness
  cipherPayPubKey: userCipherPayPubKey,
  randomness: noteRandomness,
  pathElements: merklePath.elements,
  pathIndices: merklePath.indices
});

// Share with auditor
shareWithAuditor({
  proof: auditProof.proof,
  publicSignals: auditProof.publicSignals,
  // Auditor can verify without learning identity
});
```

#### Generate Audit Withdraw Proof

```javascript
// User wants to prove they withdrew $5000 for supplier payment
const auditProof = await sdk.generateAuditWithdrawProof({
  nullifier: withdrawalNullifier,
  amount: 5000n,
  tokenId: 1n,
  memo: "Invoice #ABC123",
  
  // Private witness (NO walletPrivKey!)
  cipherPayPubKey: userCipherPayPubKey,
  randomness: noteRandomness
});

// Share with auditor
shareWithAuditor({
  proof: auditProof.proof,
  publicSignals: auditProof.publicSignals,
  // Auditor CANNOT spend with this proof
});
```

### For Auditors

#### Verify Audit Payment Proof

```javascript
import { verifyGroth16 } from 'snarkjs';

const isValid = await verifyGroth16(
  verificationKey,
  publicSignals,  // [commitment, merkleRoot, amount, tokenId, memoHash]
  proof
);

if (isValid) {
  console.log('✓ Payment verified:');
  console.log(`  Amount: ${publicSignals[2]}`);
  console.log(`  Token: ${publicSignals[3]}`);
  console.log(`  Memo hash: ${publicSignals[4]}`);
  console.log('✗ User identity: PROTECTED');
}
```

#### Verify Audit Withdraw Proof

```javascript
const isValid = await verifyGroth16(
  verificationKey,
  publicSignals,  // [nullifier, amount, tokenId, memoHash]
  proof
);

if (isValid) {
  console.log('✓ Withdrawal verified:');
  console.log(`  Amount: ${publicSignals[1]}`);
  console.log(`  Nullifier: ${publicSignals[0]}`);
  console.log('✗ Spending authority: NOT GRANTED');
  console.log('✗ User identity: PROTECTED');
}
```

---

## Security Considerations

### Privacy Guarantees

✅ **User identity protected**: `cipherPayPubKey` never disclosed  
✅ **Transaction unlinkability**: Randomness prevents linking  
✅ **Selective disclosure**: Only chosen facts revealed  
✅ **Forward privacy**: Past transactions remain private  

### Security Properties

✅ **Zero-knowledge**: Only disclosed facts proven  
✅ **Soundness**: Cannot fake proofs without witness  
✅ **Non-interactive**: Verifiable independently  
✅ **Publicly verifiable**: Anyone can check proofs  

### Audit-Specific Security

✅ **No spending authority** (audit_withdraw): Auditor cannot spend nullifier  
✅ **Limited scope**: Only proves specific transaction  
✅ **User consent**: User must generate proof voluntarily  
✅ **No backdoor**: Cannot audit without user cooperation  

---

## Compliance Applications

### Supported Use Cases

1. **Tax Compliance**
   - Charitable donation verification
   - Business expense deduction
   - Capital gains reporting

2. **Regulatory Compliance**
   - AML/KYC verification
   - Transaction monitoring
   - Suspicious activity reports

3. **Business Auditing**
   - Financial statement verification
   - Internal audit trails
   - Accounts payable/receivable

4. **Legal Proceedings**
   - Discovery requests
   - Fraud investigations
   - Contract disputes

### Compliance Best Practices

1. **Request minimum disclosure**: Only request necessary facts
2. **Verify on-chain anchoring**: Cross-check with blockchain events
3. **Respect user privacy**: Don't request full transaction history
4. **Document proof verification**: Keep audit trail of verifications
5. **Secure proof storage**: Protect audit proofs from unauthorized access

---

## FAQ

### Q: Can auditors see my other transactions?
**A**: No. Audit proofs only reveal the specific transaction being audited. Your other transactions and identity remain private.

### Q: Can auditors spend my funds after audit?
**A**: No. The audit_withdraw circuit does NOT require or reveal your `walletPrivKey`. Auditors cannot spend your nullifier or perform withdrawals.

### Q: Do I have to audit all transactions?
**A**: No. You only generate audit proofs for specific transactions you choose to disclose (e.g., for tax deductions or legal requirements).

### Q: Can someone force me to generate an audit proof?
**A**: Audit proofs require your private witness data. Without your cooperation, audit proofs cannot be generated. However, legal authorities may compel disclosure.

### Q: How does this compare to traditional privacy coins?
**A**: Traditional privacy coins (like Zcash) offer all-or-nothing privacy. CipherPay enables selective disclosure, allowing you to prove specific facts for compliance while keeping everything else private.

### Q: Can I revoke an audit proof?
**A**: Audit proofs are cryptographic statements that cannot be revoked. Once shared, they permanently prove the disclosed facts. Only share audit proofs when legally required.

---

## References

- [Main README](../README.md) - Circuit overview
- [Scripts README](../scripts/README.md) - Build scripts
- [Technical Spec](../docs/technical-spec.md) - Detailed specifications
- [CipherPay Whitepaper](../../doc/CipherPay-whitepaper-v3.txt) - System architecture

---

**Last Updated**: February 2026  
**Circuit Version**: Circom 2.1.4  
**Proving System**: Groth16
