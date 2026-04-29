# BITE on SKALE — Auditor's Context

This document is written for a Solidity audit agent reviewing contracts that import `@skalenetwork/bite-solidity`. It describes how a BITE-enabled SKALE chain differs from Ethereum, what Conditional Transactions (CTXs) are, and the invariants an auditor must keep in mind when reasoning about confidentiality, re-entrancy, gas accounting, and the callback trust boundary.

---

## 1. How SKALE (with BITE) differs from Ethereum

SKALE chains are EVM-compatible, but several runtime assumptions that hold on Ethereum do not hold on SKALE — and some new ones are introduced by BITE. An auditor should keep these in mind when analysing any contract deployed to a BITE-enabled SKALE chain.

### 1.1 Chain-level differences (SKALE, independent of BITE)

- **Gas price is fixed by the chain configuration.** `tx.gasprice` is effectively constant on SKALE (legacy transactions at the configured price). Patterns like `msg.value / tx.gasprice` to derive a gas budget are reliable in the common case, but are **unsafe if a caller submits an EIP-1559 (TYPE2) transaction** where `tx.gasprice` resolves differently, or if the chain configuration changes. Flag contracts that rely on this without either pinning the gas price or restricting the transaction type.

- **EVM version pinned to `istanbul`** for any contract touching BITE precompiles. Later EVM versions (e.g. those emitting `PUSH0`) will not execute correctly against the current SKALE runtime for contracts using these precompiles. Audit flag: Solidity ≥0.8.20 without `evmVersion: "istanbul"` in the build config.

- **Block timestamps and `block.number`** behave qualitatively like Ethereum, but SKALE chains have different block times. Time-based locks should be reviewed against the specific chain's cadence rather than Ethereum's ~12s. SKALE block mining time can be sub-second, and block-finality of 1. Block timestamps are strictly incremental.

### 1.2 BITE-specific differences

- **Three additional precompiles** at `0x1B`, `0x1C`, `0x1D` (see §3).
- **Conditional Transactions (CTXs).** A contract can submit a transaction that will be executed by the chain itself after the BITE network threshold-decrypts payloads off-chain. The callback that delivers the decrypted data is a **system-originated transaction**, not a normal user tx. See §4.
- **Encrypted storage.** The intended design is that sensitive data exists on-chain only as TE or ECIES ciphertext; decryption happens transiently during a CTX callback or off-chain if ECIES encrypted. `onDecrypt` execution trace is protected - only saved memory will be "revealed".
- **Freshly generated callback senders.** Each CTX callback is delivered from a newly generated, CTX-unique EOA-like address (`ctxSender`). Trust of `msg.sender` inside `onDecrypt` is established by whitelisting this address at submission time — never by any other means.
- **Asynchronous execution in separate transactions.** `submitCTX` returns synchronously, but `onDecrypt` fires in a *later* block. Any invariant that a reviewer would normally check with "this happens atomically within one tx" does NOT hold across a CTX boundary - should watchout close for Atomicity issues.

---

## 2. The BITE library surface (`BITE.sol`)

The library is a thin wrapper over low-level calls to the three precompiles.

| Function | Precompile | Call type | State | Returns |
|---|---|---|---|---|
| `BITE.submitCTX(addr, gasLimit, encryptedArgs, plaintextArgs)` | `0x1B` | `call` | state-changing | `address payable ctxSender` |
| `BITE.encryptTE(addr, plaintext)` | `0x1D` | `staticcall` | `view` | `bytes ciphertext` |
| `BITE.encryptECIES(addr, plaintext, PublicKey)` | `0x1C` | `staticcall` | `view` | `bytes ciphertext` |


Error surface is defined in contracts/Errors.sol in the bite-solidity repository (see `SubmitCTXErrors`, `EncryptECIESErrors`, `EncryptTEErrors`). These errors originate from the precompile itself (input decoding, key validity, RLP conversion, etc.) and propagate as typed custom errors.

### 2.1 `IBiteSupplicant`

Any contract that submits a CTX MUST implement `IBiteSupplicant.onDecrypt`

```solidity
function onDecrypt(
    bytes[] calldata decryptedArguments, // safely decrypted-from-TE payloads
    bytes[] calldata plaintextArguments  // forwarded unchanged
) external;
```

This is the entry point the BITE network invokes from `ctxSender` in a later block.

---

## 3. The BITE precompiles

### 3.1 `EncryptTE` — `0x1D` (staticcall, view-safe)

Encrypts arbitrary bytes under the **network public threshold key**. Only the BITE network (via a threshold of nodes) can decrypt. When an account submits the request, it's address is saved in the cyphertext. Only that account is allowed to schedule decryption of such values - otherwise anyone could write a contract to decrypt any value encrypted by another account.

### 3.2 `EncryptECIES` — `0x1C` (staticcall, view-safe)

Encrypts arbitrary bytes under a specific secp256k1 public key supplied by the caller. Only the holder of the corresponding private key can decrypt, **and this decryption happens off-chain** — there is no on-chain ECIES decryption precompile. ECIES is the mechanism for targeted disclosure (e.g. re-encrypting decrypted TE material to one specific viewer inside `onDecrypt`).

### 3.3 `SubmitCTX` — `0x1B` (call, state-changing)

Enqueues a conditional transaction. Inputs:

- `gasLimit` — gas budget that will be handed to the callback transaction.
- `encryptedArguments: bytes[]` — each element must be a TE ciphertext; the network decrypts each one before the callback.
- `plaintextArguments: bytes[]` — forwarded to the callback unchanged.

Returns: a freshly generated `address payable ctxSender`, unique to this CTX, from which the `onDecrypt` callback will be invoked.

**Funding the callback.** The `ctxSender` address must hold at least `gasLimit * tx.gasprice` of gas token at the time the callback is executed, or the network will not fire the callback (it will fail due to lack of funds). The conventional pattern is (msg value or any value):

```solidity
ctxSender = BITE.submitCTX(BITE.SUBMIT_CTX_ADDRESS, msg.value / gasprice, encArgs, ptArgs);
payable(ctxSender).sendValue(msg.value);
```

Where gasPrice is the constant gas price on SKALE.

---

## 4. Conditional Transactions (CTXs) — full Solidity lifecycle

This section is the core of what an auditor needs to understand. A CTX is a **two-transaction flow** with a trust-boundary crossing in the middle.

### 4.1 Transaction 1 — Submission

Caller (EOA or contract) invokes a user-facing function on the supplicant contract (call it `requestReveal(...)`):

```solidity
function requestReveal(bytes calldata someEncryptedInput) external payable {
    bytes[] memory encryptedArgs = new bytes[](1);
    encryptedArgs[0] = someEncryptedInput; // must be valid TE ciphertext

    bytes[] memory plaintextArgs = new bytes[](1);
    plaintextArgs[0] = abi.encode(msg.sender); // example: operation metadata

    uint256 gasBudget = msg.value / tx.gasprice;
    require(gasBudget >= MIN_CALLBACK_GAS, NotEnoughValueSentForGas());

    address payable ctxSender = BITE.submitCTX(
        BITE.SUBMIT_CTX_ADDRESS,
        gasBudget,
        encryptedArgs,
        plaintextArgs
    );

    _canCallOnDecrypt[ctxSender] = true;  // authorise exactly this ctxSender
    ctxSender.sendValue(msg.value);       // fund the callback
}
```

Step-by-step semantics during this transaction:

1. `BITE.submitCTX` performs a low-level `call` to `0x1B` with ABI-encoded `(gasLimit, abi.encode(encryptedArgs, plaintextArgs))`.
2. The precompile validates: shape, encoded offsets, TE-ciphertext sizes, destination (the calling contract), signature/transaction construction internals. Any failure reverts with a typed `CTX*` error from `SubmitCTXErrors`.
3. On success, the precompile returns a 20-byte `ctxSender` address and emits `CTXSubmitted(ctxSender)` (from the library, not the precompile).
4. The supplicant contract **must** record authorisation of this `ctxSender` before the transaction ends (typically `_canCallOnDecrypt[ctxSender] = true`). It **must** also transfer enough value to `ctxSender` to cover `gasLimit * tx.gasprice`.
5. Transaction 1 ends. No decryption has happened yet. Nothing has been revealed. It is essential that state-changes remain atomic - if a transaction depends on a CTX, make all state changes during the `onDecrypt` callback.

### 4.2 Between transactions — BITE network work

The network observes the CTX, performs threshold decryption of each `encryptedArgument` off-chain (requires a threshold of honest nodes cooperating), and constructs a system transaction that will invoke `onDecrypt` on the supplicant from `ctxSender`.

This happens in a later block. The guarantees are as follows:
- CTXs are scheduled for the **next block** (N+1).
- Each block still verifies gasLimit, thus if for some reason the amount of CTXs scheduled for block N+1 is too much, the remaining CTXs are re-scheduled for block N+2, and so on. decrypted CTXs take precedence over regular transactions - when picking transactions for a block, first the block is filled with CTXs.
- Order is guaranteed - CTXs are executed by the same order they are scheduled. However, between CTX submission and execution, other state changes can occurr by other transactions.

### 4.3 Transaction 2 — Callback (`onDecrypt`)

A system-originated transaction with `msg.sender == ctxSender` invokes `onDecrypt` with:

- `decryptedArguments[i]` — the plaintext of `encryptedArguments[i]` submitted earlier.
- `plaintextArguments[i]` — the corresponding element of `plaintextArguments` from submission, forwarded unchanged.

The supplicant must enforce the following invariants in this order:

```solidity
function onDecrypt(
    bytes[] calldata decryptedArgs,
    bytes[] calldata plaintextArgs
) external override {
    // (1) Authenticate msg.sender against the whitelist populated in submitCTX.
    require(_canCallOnDecrypt[msg.sender], AccessDenied());

    // (2) One-shot: prevent replay if the system ever re-delivers.
    _canCallOnDecrypt[msg.sender] = false;

    // (3) Dispatch: if one contract multiplexes several CTX flows,
    //     distinguish them by arg shape OR by an explicit discriminator
    //     in plaintextArgs.
}
```

NOTE: This pattern does not clear senders from failed transactions. This is considered safe because it is considered *impossible* to get the key for such address to re-sign a transaction. The state is changed to `false` on successfull ones to minimze used storage.


### 4.5 Re-entrancy and state consistency

- `submitCTX` is a `call` to a system precompile. The precompile is trusted and performs no external calls back into user contracts. **Re-entrancy from the precompile itself is not possible.**
- However, `onDecrypt` runs in a **later transaction** with arbitrary contract state evolved in between. Anything a normal tx can do (price changes, role changes, pauses, upgrades) can have happened between submission and callback. Treat the callback as a fresh, adversarially-scheduled tx with respect to every state variable that is not explicitly snapshotted into `plaintextArguments`, storage keyed on `ctxSender`, or the encrypted payload.
- Multiple CTXs can be in flight simultaneously. `onDecrypt` may be invoked with interleavings unrelated to submission order. Per-CTX state should be keyed on `ctxSender`, not on globals.
- `onDecrypt` itself may call `submitCTX` (self-referential CTX chains). This means a callback can submit further CTXs whose callbacks will fire later. Audit for unbounded recursion / gas griefing and for correct termination conditions.

### 4.6 Gas accounting inside `onDecrypt`

The callback is executed with exactly `GAS_LIMIT` gas (the value passed to `submitCTX`). If `onDecrypt` runs out of gas, the callback reverts, and (depending on chain behaviour and the refund policy) the CTX may be dropped.

### 4.7 What can go wrong with the plaintext once it is inside `onDecrypt`

The plaintext exists in memory for the duration of the callback. Audit for:

- Writing plaintext to storage (makes it world-readable forever).
- Emitting plaintext in events (events are public).
- Don't trust passing plaintext to other (arbitrary) contracts in non-view functions.
- Verify re-encryption of said sensitive texts (usualy via ECIES), and what Public Key is used

A correctly-written supplicant either (a) re-encrypts the plaintext under ECIES for a specific viewer and stores the ECIES ciphertext, or (b) uses the plaintext to drive a single decision (e.g. "did this bidder offer >= reserve?") and discards it without persistence.

---

## 5. Consensus and block-rule behaviour of CTXs

- SKALE networks have a fixed block limit.
- CTXs, once scheduled, are saved to be executed in the first available block after the one they're scheduled in. They take priority over regular transactions, thus if there are pending CTXs for a given block, other transactions are put on hold untill a block has space for them.
- We can assume execution context (trace) of CTXs (onDecrypt) is hidden, only saved storage/events are revealed as usual.
- CTXs are executed in the exact same order they are scheduled.
- For each CTX, a random address is generated to be the sender of such CTX. This address is known upon CTX scheduling, and should be topped up with gas enough to pay for the CTX, otherwise it fails (CTX may not appear in the block)
