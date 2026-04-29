# Audit Findings — ConfidentialToken System

**Repository:** skalenetwork/confidential-token  
**Auditor:** GitHub Copilot Security Audit Agent  
**Scope:** All contracts in `contracts/` (primary) and `test/`, `migrations/`, `scripts/` (supporting)  
**Date:** 2025

---

## Findings

*(Ordered by descending severity)*

---

### F-01 — `withdrawTo` Ignores the `account` Parameter: Underlying Tokens Always Sent to the Burner

**Severity:** High  
**Files/functions:** `contracts/ConfidentialWrapper.sol` — `withdrawTo`, `_onBurn`

**Root cause:**  
`ConfidentialWrapper.withdrawTo(address account, uint256 value)` overrides `ERC20Wrapper.withdrawTo` but never passes `account` into the asynchronous callback. The burn is submitted for `_msgSender()`, and when the BITE callback fires, `_onUpdate` calls `_onBurn(from=_msgSender(), value)`, which executes `underlying().safeTransfer(from, value)`. The `account` argument is validated only against `address(this)` (to prevent self-withdrawal) and is otherwise completely discarded.

**Attack or failure scenario:**  
1. Alice calls `token.withdrawTo(bob, 100)` expecting 100 underlying tokens to be sent to Bob.  
2. The BITE callback fires, calling `_onBurn(alice, 100)`.  
3. `underlying().safeTransfer(alice, 100)` is executed — Alice receives the tokens, not Bob.  
4. The return value of `withdrawTo` is `true`, giving no indication of the misdirection.

More impactfully, any integration that uses `withdrawTo(thirdParty, value)` to deliver underlying tokens to a recipient — e.g., a DEX adapter or router — will find that tokens are delivered to the contract or EOA that initiated the withdrawal rather than the intended recipient.

**Impact:**  
- Token misdirection: users cannot withdraw to a specified beneficiary.  
- ERC20Wrapper interface contract violated; integrations relying on ERC20Wrapper semantics (tokens go to `account`) silently break.  
- Funds are not lost (they go to the caller), but the expected third-party destination receives nothing.

**Proof or reasoning:**  
```solidity
// ConfidentialWrapper.sol:89-95
function withdrawTo(address account, uint256 value) public override returns (bool success) {
    if (account == address(this)) {
        revert ERC20InvalidReceiver(account);
    }
    _burn(_msgSender(), value);  // account is never stored or forwarded
    return true;
}

// ConfidentialWrapper.sol:139-141
function _onBurn(address from, uint256 value) private {
    underlying().safeTransfer(from, value);  // from = _msgSender() of withdrawTo, not account
}
```

Compare with OZ `ERC20Wrapper.withdrawTo`:
```solidity
// OpenZeppelin reference:
function withdrawTo(address account, uint256 value) public virtual returns (bool) {
    _burn(msgSender, value);
    SafeERC20.safeTransfer(underlying(), account, value);  // sends to account
}
```

**Recommended fix:**  
Store the intended recipient in the BITE plaintext arguments alongside the `TransferInfo` struct, or create a separate `WithdrawInfo` struct. Pass `account` through the callback so that `_onBurn` can direct the underlying token transfer to the correct address.

```solidity
// Example: store account in plaintextArguments during _encryptedUpdate for burns
// Then in _onBurn retrieve and use account
```

Alternatively, if withdrawals are always to `msg.sender` (no delegation), document this clearly and remove the misleading `account` parameter, making the function `withdrawTo(uint256 value)`.

**Tests to add or update:**  
- `withdrawTo(bob, amount)` called by alice: assert that bob receives the underlying tokens, not alice.  
- `withdrawTo(address(this), amount)`: assert `ERC20InvalidReceiver` is reverted.

**Confidence:** High

---

### F-02 — `depositFor(account, value)` with `account ≠ msg.sender` Creates `requestedMints` Mismatch, Enabling Griefing and Permanent Fund Loss

**Severity:** High  
**Files/functions:** `contracts/ConfidentialWrapper.sol` — `depositFor`, `_onMint`, `releaseTo`

**Root cause:**  
`ConfidentialWrapper.depositFor` increments `requestedMints[msg.sender]`, but the BITE callback's `_onMint(to, value)` decrements `requestedMints[to]` (the mint recipient). When `account ≠ msg.sender`, these are two different slots. The depositor's `requestedMints` grows while the recipient's `requestedMints` is consumed.

**Attack or failure scenario:**  

*Scenario A — Normal third-party deposit always fails:*  
1. Alice calls `depositFor(bob, 100)`: `requestedMints[alice] = 100`, 100 underlying moves to wrapper, CTX submitted to mint 100 for Bob.  
2. Callback fires: `_onMint(bob, 100)` → `requestedMints[bob] -= 100`. If Bob has no pending mints, this underflows and the call reverts with `OutdatedMint`. No tokens are minted for Bob.  
3. Alice calls `releaseTo(alice, 100)` to recover her underlying. Bob's balance is unchanged.  
Result: third-party deposits are non-functional by default.

*Scenario B — Griefing/fund-loss attack (front-running):*  
1. Bob calls `depositFor(bob, 100)`: `requestedMints[bob] = 100`, 100 underlying → wrapper. CTX-bob submitted.  
2. Attacker (Eve) calls `depositFor(bob, 50)` BEFORE CTX-bob fires: `requestedMints[eve] = 50`, 50 underlying → wrapper. CTX-eve submitted.  
3. CTX-eve fires first (e.g., in same block with Eve front-running): `_onMint(bob, 50)` → `requestedMints[bob] = 50`. Bob receives 50 confidential tokens.  
4. CTX-bob fires: `_onMint(bob, 100)` → `requestedMints[bob] = 50 - 100` → underflows → `OutdatedMint` reverts.  
5. Bob's 100 underlying is locked in wrapper. `requestedMints[bob] = 50` (not enough to recover 100). Bob can only call `releaseTo(bob, 50)`, recovering 50 underlying.  
6. Eve calls `releaseTo(eve, 50)` to recover her 50 underlying.  
Result: Bob permanently loses 50 underlying tokens with no recovery path. Eve loses nothing.

**Impact:**  
- Permanent partial loss of underlying funds for victims (attackers pay only gas).  
- `depositFor(account, value)` is functionally broken for `account ≠ msg.sender` in any concurrent environment.  
- Wrapper's 1:1 backing is not violated (over-backing occurs), but victim's individual claim is lost.

**Proof or reasoning:**  
```solidity
// ConfidentialWrapper.sol:83-86
function depositFor(address account, uint256 value) public override returns (bool success) {
    requestedMints[msg.sender] += value;  // tracks depositor (msg.sender)
    return super.depositFor(account, value);
}

// ConfidentialWrapper.sol:130-137
function _onMint(address to, uint256 value) private {
    bool previouslyRequested;
    (previouslyRequested, requestedMints[to]) = Math.trySub(
        requestedMints[to],   // checks recipient (to), not depositor
        value
    );
    require(previouslyRequested, OutdatedMint(to, value));
}
```

The mismatch: `requestedMints[msg.sender]` is incremented but `requestedMints[to]` is decremented. When `msg.sender ≠ to`, the wrong slot is decremented.

**Recommended fix:**  
Track `requestedMints` by recipient (the `account` argument to `depositFor`), not by caller:

```solidity
function depositFor(address account, uint256 value) public override returns (bool success) {
    requestedMints[account] += value;  // FIX: use account, not msg.sender
    return super.depositFor(account, value);
}
```

Then update `releaseTo` to require a separate recovery mechanism for depositors, since the `requestedMints` now belongs to the recipient, not the depositor. Consider tracking depositor separately for the emergency recovery path.

**Tests to add or update:**  
- `depositFor(bob, 100)` called by alice: assert callback succeeds only if `requestedMints[bob] >= 100` before the call.  
- Concurrent `depositFor(bob, 100)` by bob and `depositFor(bob, 50)` by attacker: assert both succeed or the attacker's partial interference does not cause fund loss.  
- `releaseTo` after failed third-party deposit: assert depositor recovers correct amount.

**Confidence:** High

---

### F-03 — EIP-3009 and Plain Allowance Nonces/Allowances Consumed Before CTX Finality

**Severity:** Medium  
**Files/functions:** `contracts/eip3009/ConfidentialEIP3009.sol` — `_transferWithAuthorization`; `contracts/ConfidentialToken.sol` — `_handleTransferRequest`

**Root cause:**  
In `ConfidentialEIP3009._transferWithAuthorization`, the nonce is permanently marked as used (`_authorizationStates[from][nonce] = true`) before the CTX transfer fires. For plain EIP-3009 (non-confidential), the `EIP3009._transferWithAuthorization` also marks the nonce and then calls `_transfer` which calls `_update` → submits a CTX.

In `_handleTransferRequest`, for `transferFrom` operations with a spender, `_spendAllowance` is called before the staleness check. If the callback subsequently fails in the resubmission phase (e.g., `_encryptedUpdate` reverts because gasPayer has no ETH), the entire callback reverts — restoring the allowance — but the callback fee already sent to `ctxSender` is consumed.

**Attack or failure scenario:**  

*EIP-3009 nonce loss:*  
1. Alice signs an `encryptedTransferWithAuthorization` nonce=N authorizing 100 tokens to Bob.  
2. Charlie (relayer) submits the authorization. At this point, if `_encryptedTransfer` reverts (e.g., Alice has 0 ETH in `_ethBalance`), the entire call reverts including the nonce update. However, if the CTX is successfully submitted but the callback eventually reverts (e.g., due to InsufficientBalance), the nonce is still marked used but no tokens move.  
3. Alice's nonce N is permanently consumed. A new authorization with a new nonce is required, and the relayer effectively denied service for the original authorization.

*Callback fee loss on transferFrom:*  
1. Bob calls `transferFrom(alice, bob, 100)` at a moment when Alice has given Bob allowance.  
2. Bob's ETH fee is deducted, CTX submitted.  
3. Callback fires: allowance consumed, state is stale, `_updateWithGasPayer` is called.  
4. If Bob's `_ethBalance` has since fallen below `callbackFee`, `_updateWithGasPayer` reverts — the callback reverts, restoring the allowance but NOT restoring the initial fee paid in step 2.  
5. Bob lost a callback fee, alice's allowance is intact, no transfer occurred.

**Impact:**  
- EIP-3009 authorizations can be permanently burned by a malicious relayer or race condition without any token movement.  
- Callback fees are non-refundable even when transfers fail due to insufficient resubmission funds.  
- In the case of resubmission loops (stale state), gasPayer's ETH can be drained: each resubmission deducts a callback fee. With no cap on resubmissions, a determined adversary with concurrent transfers can drain the gasPayer's ETH balance across multiple resubmissions.

**Proof or reasoning:**  
```solidity
// ConfidentialEIP3009.sol:199-202
_authorizationStates[from][nonce] = true;  // nonce consumed
emit AuthorizationUsed(from, nonce);
_encryptedTransfer(from, to, value);       // CTX submitted → callback may fail later
```

```solidity
// ConfidentialToken.sol:490-504
if(transferInfo.spender != address(0)) {
    _spendAllowance(transferInfo.from, transferInfo.spender, value);  // consumed before...
}
if (_lastChanged[...] > transferInfo.submittedBlockNumber) {  // ...staleness check
    _updateWithGasPayer(...);  // may fail if gasPayer has no ETH
    return;
}
```

**Recommended fix:**  
- For EIP-3009: Document clearly that nonces are consumed upon CTX submission and are not refunded on callback failure. Consider adding a mechanism to "cancel" pending CTX nonces if the callback doesn't fire within a timeout.  
- For stale-state resubmission: Add a cap on resubmission count (store resubmission count in plaintext args). After N resubmissions, allow the user to cancel and reclaim any remaining ETH.  
- Emit a specific event when resubmission occurs to allow off-chain monitoring.

**Tests to add or update:**  
- `encryptedTransferWithAuthorization` where callback reverts due to InsufficientBalance: assert nonce is consumed and transfer doesn't happen.  
- `transferFrom` where gasPayer's ETH runs out during resubmission: assert allowance is restored but initial fee is lost.  
- Concurrent transfers from same account: assert number of resubmission events matches expected.

**Confidence:** High

---

### F-04 — `callbackFee / tx.gasprice` Integer Truncation Can Produce Zero Gas Limit

**Severity:** Medium  
**Files/functions:** `contracts/ConfidentialToken.sol` — `requestDecryptHistoricTransferFor` (line 376), `_encryptedUpdate` (line 664)

**Root cause:**  
The gas limit passed to `BITE.submitCTX` is computed as `callbackFee / tx.gasprice`. Since both are `uint256`, integer division truncates. If `callbackFee < tx.gasprice`, the result is 0, meaning the CTX callback would receive 0 gas — it cannot execute.

Additionally, if the chain is configured with `tx.gasprice = 0` (zero gas price, unusual but possible on some SKALE chain configurations), this causes a division-by-zero revert, preventing any CTX submission.

**Attack or failure scenario:**  
1. The gas price on the SKALE chain is configured at 500 gwei.  
2. Admin sets `callbackFee` to 400 gwei via `setCallbackFee`.  
3. All CTX submissions compute gas limit = `400 gwei / 500 gwei = 0`.  
4. All BITE callbacks receive 0 gas. The BITE network cannot execute them (or executes and immediately OOGs).  
5. All transfers, mints, burns, and viewer-key updates are permanently stuck.

**Impact:**  
- Complete denial of service: no token operations can finalize until a valid callback fee is set.  
- Funds may be stuck in pending CTX state if callbacks can't execute.  
- On a chain with zero gas price configured, any call to functions that submit CTXs reverts.

**Proof or reasoning:**  
```solidity
// ConfidentialToken.sol:664
address payable callback = BITE.submitCTX(
    submitCTXAddress,
    callbackFee / tx.gasprice,  // truncates to 0 if fee < gasprice
    encryptedArguments,
    plaintextArguments
);
```

On SKALE, gas price is fixed but could vary if the chain is upgraded or a different gas price unit is used.

**Recommended fix:**  
1. Validate that `callbackFee / tx.gasprice > MINIMUM_CALLBACK_GAS` in `_encryptedUpdate` and `requestDecryptHistoricTransferFor`.  
2. Alternatively, have `setCallbackFee` enforce that `newFee >= MINIMUM_CALLBACK_GAS * tx.gasprice` at set time.  
3. Add a check that `tx.gasprice > 0` before division.

```solidity
uint256 gasLimit = callbackFee / tx.gasprice;
require(gasLimit >= MINIMUM_CALLBACK_GAS, InsufficientGasLimit(gasLimit));
```

**Tests to add or update:**  
- `setCallbackFee(0)` followed by a transfer: assert the CTX is submitted with 0 gas limit and fails.  
- `setCallbackFee(X)` where X < gas_price: assert appropriate error is thrown.

**Confidence:** High

---

### F-05 — Historic View Fee Charged Before Authorization Verified at Callback Time

**Severity:** Medium  
**Files/functions:** `contracts/ConfidentialToken.sol` — `requestDecryptHistoricTransferFor`; `contracts/HistoricView.sol` — `decodeIfAuthorized`

**Root cause:**  
`requestDecryptHistoricTransferFor` deducts the `callbackFee` from `msg.sender._ethBalance` and submits the CTX immediately. Authorization is only verified inside the callback via `_historicViewAuth.decodeIfAuthorized`. If the holder revokes authorization between the request submission and the callback execution, the callback reverts with `UserIsNotAuthorizedToDecryptTransfer`, but the fee is permanently lost.

**Attack or failure scenario:**  

*Holder griefing a viewer:*  
1. Alice grants Bob time-range access to her transfers.  
2. Bob calls `requestDecryptHistoricTransfer(encryptedData)` — fee deducted.  
3. Before the callback fires (same or next block), Alice calls `removeHistoricViewAuth(bob)`.  
4. Callback fires: `_isAuthorized` returns false → revert.  
5. Bob loses his callback fee with no transfer decryption.  
This can be repeated to drain Bob's ETH balance.

*Accidental loss:*  
Alice revokes access inadvertently between Bob's request and the callback. Bob loses the fee. No compensation mechanism exists.

**Impact:**  
- Holders can grief authorized viewers by revoking access just before callback execution.  
- Viewers lose callback fees with no refund and no transfer data.  
- The README documents "Charges callbackFee from msg.sender even if not authorized" — this is acknowledged but the revocation timing race makes it exploitable.

**Proof or reasoning:**  
```solidity
// ConfidentialToken.sol:364-383
require(_ethBalance[msg.sender] >= callbackFee, ...);
_ethBalance[msg.sender] -= callbackFee;  // fee taken immediately
...
address payable callback = BITE.submitCTX(...);  // CTX submitted

// Holder can call removeHistoricViewAuth() between here and the callback firing

// In callback:
// HistoricView.sol:140-143
require(
    _isAuthorized(authStorage, transferData, sender),
    UserIsNotAuthorizedToDecryptTransfer(sender, transferData.transferId)  // fee already gone
);
```

**Recommended fix:**  
- Snapshot the authorization state into `plaintextArguments` at request time and verify consistency at callback time. However, this would allow bypassing revocations.  
- A better approach: allow the viewer to request a refund if the callback reverts due to authorization failure (emit a specific event and allow a claim).  
- At minimum, add documentation clarifying the griefing risk and advising viewers to check `canDecryptHistoricTransfer` off-chain before spending the fee.  
- Rate-limit revocations or add a cool-down period after granting access.

**Tests to add or update:**  
- Grant access → request decrypt → revoke → callback: assert callback reverts AND fee is not refunded.  
- Multiple rapid revocation attacks: measure total ETH drained from viewer.

**Confidence:** High

---

### F-06 — Unbounded CTX Resubmission Can Drain `gasPayer` ETH Balance

**Severity:** Medium  
**Files/functions:** `contracts/ConfidentialToken.sol` — `_handleTransferRequest`, `_updateWithGasPayer`

**Root cause:**  
When `_handleTransferRequest` detects a stale state (`_lastChanged[from] > submittedBlockNumber || _lastChanged[to] > submittedBlockNumber`), it calls `_updateWithGasPayer`, which deducts another `callbackFee` from `_ethBalance[gasPayer]` and submits a new CTX. If the state is still changing when the new callback fires, another resubmission occurs. There is no limit on the number of resubmissions.

**Attack or failure scenario:**  
1. Alice's account is the target of frequent concurrent transfers (e.g., many EIP-3009 signed transfers submitted simultaneously by relayers).  
2. Each incoming transfer creates a CTX. When two CTXs overlap, the second always finds a stale state and resubmits.  
3. Each resubmission charges `callbackFee` from the original `gasPayer` (which could be Alice's EIP-3009 relayer).  
4. With N concurrent transfers, up to N * (N-1) / 2 extra resubmissions can occur, each consuming a callback fee.  
5. If the `gasPayer`'s ETH balance is drained, the resubmission fails, the callback reverts — but prior fees are already consumed.

**Impact:**  
- gasPayer's ETH balance can be drained without proportional transfer execution.  
- Relayers for EIP-3009 transfers can be griefed by submitting many concurrent transfers targeting the same recipient or sender.

**Proof or reasoning:**  
```solidity
// ConfidentialToken.sol:498-505
if (_lastChanged[transferInfo.from] > transferInfo.submittedBlockNumber ||
    _lastChanged[transferInfo.to] > transferInfo.submittedBlockNumber) {
    emit CTXResubmitted(msg.sender);
    _updateWithGasPayer(transferInfo.from, transferInfo.to, transferInfo.gasPayer, value);
    // gasPayer charged again — no limit on how many times this fires
    return;
}
```

**Recommended fix:**  
- Add a `resubmitCount` field to `TransferInfo` (in `plaintextArguments`) and cap at a reasonable maximum (e.g., 3-5).  
- If the cap is reached, emit an event and allow the gasPayer to reclaim any remaining ETH.  
- Alternatively, use a fixed gas budget per transfer that is computed once from the initial fee.

**Tests to add or update:**  
- Submit N concurrent transfers from same sender: assert total fees charged ≤ N × 2 × callbackFee (one initial + one resubmission each).  
- Induce resubmission beyond the cap: assert graceful failure rather than infinite loop.

**Confidence:** Medium

---

### F-07 — `allowance` Consumed in Callback When Transfer is Re-Submitted Without Spender

**Severity:** Medium  
**Files/functions:** `contracts/ConfidentialToken.sol` — `_handleTransferRequest`

**Root cause:**  
In `_handleTransferRequest`, the `_spendAllowance` call occurs BEFORE the staleness check. If the state is stale, the callback calls `_updateWithGasPayer` (a resubmission without the `spender` field). The allowance is thus consumed in the first callback but the resubmitted CTX carries `spender = address(0)` — meaning no allowance is checked on the second callback. If the resubmission's callback reverts for any reason, the entire resubmission transaction reverts (restoring the allowance), but the first callback already consumed it at the point where control passed to `_updateWithGasPayer`.

**Attack or failure scenario:**  
1. Spender submits `transferFrom(alice, bob, 100)`.  
2. Alice's `_ethBalance` runs out between CTX submission and callback.  
3. Callback 1 fires: `_spendAllowance(alice, spender, 100)` — allowance consumed.  
4. State is stale → `_updateWithGasPayer` fails because gasPayer has no ETH.  
5. Callback 1 reverts entirely — allowance is restored.  
6. Initial fee is still consumed.

While the allowance is ultimately safe in this scenario (revert restores it), the sequencing creates a subtle window where the allowance appears consumed during callback 1's execution, and external observers (or reentrancy-capable underlying tokens in ConfidentialWrapper) may act on the temporary state.

**Impact:**  
- Low immediate impact under pure Solidity reverts.  
- If the underlying token's `safeTransfer` in `_onBurn` triggers a callback that reads allowance state, it could see a transiently consumed allowance.  
- Conceptually confusing: allowance is consumed before it is clear whether the transfer will succeed.

**Proof or reasoning:**  
```solidity
// ConfidentialToken.sol:490-505
if(transferInfo.spender != address(0)) {
    _spendAllowance(transferInfo.from, transferInfo.spender, value);  // step A
}
...
if (_lastChanged[...] > transferInfo.submittedBlockNumber) {
    _updateWithGasPayer(...);  // step B: may fail, causing revert that undoes step A
    return;
}
```

**Recommended fix:**  
Move `_spendAllowance` to AFTER the staleness check (before `_decryptedUpdate`), or pass the spender through the resubmission chain so it can be checked in the final settled callback only.

**Tests to add or update:**  
- `transferFrom` with stale state: assert allowance is unchanged after resubmission.  
- `transferFrom` where gasPayer runs out of ETH in resubmission: assert allowance is unchanged.

**Confidence:** Medium

---

### F-08 — `_isValidPublicKey` Accepts Degenerate Secp256k1 Points

**Severity:** Low  
**Files/functions:** `contracts/ConfidentialToken.sol` — `_isValidPublicKey`

**Root cause:**  
```solidity
function _isValidPublicKey(PublicKey memory publicKey) private pure returns (bool isValid) {
    return publicKey.x != bytes32(0) || publicKey.y != bytes32(0);
}
```

This check accepts any key where at least one coordinate is non-zero, including points like `(x=valid, y=0)` or `(x=0, y=valid)`. On the secp256k1 curve, `y = 0` only occurs at the point at infinity (not a valid affine point), and `x = 0` is similarly exceptional. The ECIES precompile may accept or reject such keys at runtime.

**Attack or failure scenario:**  
1. A user registers `{x: someValidX, y: 0}` as their public key.  
2. The `registerPublicKey` call succeeds on-chain.  
3. When balances are encrypted for this viewer, `BITE.encryptECIES(encryptECIESAddress, data, key)` is called.  
4. If the ECIES precompile rejects the degenerate key, the entire `_setBalance` call reverts, meaning the balance cannot be updated.  
5. All transfers to/from this account are permanently blocked.

**Impact:**  
- Account self-denial: a user who registers a bad key blocks all transfers involving them.  
- No recovery mechanism (public keys are immutable once registered).

**Proof or reasoning:**  
The secp256k1 curve equation is `y² = x³ + 7 mod p`. A point with `y = 0` satisfies `0 = x³ + 7` which has no solution modulo the secp256k1 prime (7 is not a cubic residue mod p). So `(x, 0)` is never a valid secp256k1 point.

**Recommended fix:**  
Perform explicit curve membership validation: check that both coordinates are non-zero, or delegate validation to the precompile by attempting a test encryption in the registration function.

```solidity
function _isValidPublicKey(PublicKey memory publicKey) private pure returns (bool isValid) {
    return publicKey.x != bytes32(0) && publicKey.y != bytes32(0);
}
```

(Note: changing OR to AND rejects keys where either coordinate is zero.)

**Tests to add or update:**  
- Register `{x: validX, y: 0}`: assert `InvalidPublicKey` reverts (currently passes).  
- Register `{x: 0, y: validY}`: assert `InvalidPublicKey` reverts (currently passes).

**Confidence:** High

---

### F-09 — ERC20 Standard `Transfer(address,address,uint256)` Event Not Emitted

**Severity:** Low  
**Files/functions:** `contracts/ConfidentialToken.sol` — `_onUpdate`; `contracts/interfaces/IConfidentialToken.sol`

**Root cause:**  
`IConfidentialToken` declares `event Transfer(address indexed from, address indexed to)` (without `uint256 value`). This shadows the ERC20 `event Transfer(address indexed from, address indexed to, uint256 value)`. `ConfidentialToken._update` overrides `ERC20._update` and never calls `super._update`, so the standard ERC20 Transfer event is never emitted. The custom 2-argument event has selector `keccak256("Transfer(address,address)")`, not the standard `keccak256("Transfer(address,address,uint256)")`.

**Impact:**  
- All wallets, block explorers, and indexers that listen for ERC20 `Transfer` events will see no token movements.  
- ERC20 compatibility is partially broken: `balanceOf` always reverts (by design), standard Transfer events are missing.  
- Any protocol composing with this token through the ERC20 interface will behave incorrectly.

**Proof or reasoning:**  
```solidity
// IConfidentialToken.sol:59
event Transfer(address indexed from, address indexed to);  // 2-arg, non-standard

// ConfidentialToken.sol:565
emit Transfer(from, to);  // emits the non-standard 2-arg event
```

**Recommended fix:**  
This is an intentional confidentiality tradeoff: emitting the value would leak the transfer amount. Document explicitly that this contract does not emit the standard ERC20 Transfer event and is not compatible with standard ERC20 tooling for balance/transfer tracking. Consider renaming the custom event (e.g., `ConfidentialTransfer`) to avoid shadowing the ERC20 standard event.

**Tests to add or update:**  
- Assert that `Transfer(address,address,uint256)` is NOT emitted.  
- Assert that the custom `Transfer(address,address)` IS emitted with correct from/to.

**Confidence:** High

---

### F-10 — Solidity 0.8.30 with `evmVersion: "istanbul"` May Generate Invalid Opcodes for SKALE Runtime

**Severity:** Low  
**Files/functions:** `hardhat.config.ts`

**Root cause:**  
The Hardhat configuration uses `solidity: { version: "0.8.30", settings: { evmVersion: "istanbul" } }`. Solidity 0.8.20+ introduced `PUSH0` (Shanghai opcode) as a default. With `evmVersion: "istanbul"`, the compiler avoids Shanghai opcodes. However, newer Solidity versions have additional features (e.g., 0.8.24+ features) that may internally generate opcodes not available on Istanbul EVM. BITE.md explicitly warns: "EVM version pinned to `istanbul` for any contract touching BITE precompiles."

**Impact:**  
- If the Solidity 0.8.30 compiler generates any non-Istanbul opcode despite the setting, contracts may fail to execute on the SKALE runtime.  
- OpenZeppelin 5.4.0 (used as a dependency) was compiled for modern EVM; if any OZ internal code path uses post-Istanbul opcodes, it would fail.

**Proof or reasoning:**  
Solidity 0.8.30 with `evmVersion: "istanbul"` should not generate `PUSH0` or `MCOPY`. However, new features added in 0.8.27+ (e.g., custom error improvements, new intrinsics) should be verified against the SKALE EVM runtime's actual Istanbul support level.

**Recommended fix:**  
- Verify the exact SKALE node version's EVM opcode support and compare against Solidity 0.8.30's istanbul output.  
- If possible, use a verified-compatible Solidity version (e.g., 0.8.20 with istanbul) to minimize risk.  
- Run the compiled bytecode against the SKALE EVM in CI/CD before deployment.

**Tests to add or update:**  
- Deploy all contracts to a SKALE testnet and run the full test suite against the live precompiles, not just the mock.

**Confidence:** Low

---

### F-11 — Fee-on-Transfer Underlying Tokens Cause Backing Mismatch in `ConfidentialWrapper`

**Severity:** Low  
**Files/functions:** `contracts/ConfidentialWrapper.sol` — `depositFor`, `_onBurn`

**Root cause:**  
`ConfidentialWrapper` inherits from `ERC20Wrapper` which uses `safeTransferFrom` to move underlying tokens. If the underlying token charges a fee on transfer (deflation/tax tokens), the wrapper receives fewer tokens than `value` but mints the full `value` of confidential tokens. On withdrawal, the wrapper tries to transfer `value` underlying tokens back but only has `value - fee` in its balance.

**Attack or failure scenario:**  
1. Wrapper is deployed for a 2% fee-on-transfer token.  
2. User calls `depositFor(user, 100)` — 100 underlying sent, wrapper receives 98 (fee deducted).  
3. 100 confidential tokens are minted.  
4. User calls `withdrawTo(user, 100)` — callback fires, wrapper tries to send 100 underlying.  
5. If wrapper only has 98 underlying (no other deposits), the transfer fails, callback reverts.

**Impact:**  
- Wrapper is not backed 1:1 for fee-on-transfer tokens.  
- Withdrawals may fail if wrapper balance is insufficient.

**Recommended fix:**  
Document that `ConfidentialWrapper` is not compatible with fee-on-transfer tokens. Consider adding a check that measures the actual received amount versus the requested amount:

```solidity
uint256 before = underlying().balanceOf(address(this));
super.depositFor(account, value);
uint256 actual = underlying().balanceOf(address(this)) - before;
require(actual == value, "Fee-on-transfer not supported");
```

**Confidence:** Medium

---

### F-12 — `releaseTo` Allows Depositor to Redirect Locked Tokens to Any Address

**Severity:** Low  
**Files/functions:** `contracts/ConfidentialWrapper.sol` — `releaseTo`

**Root cause:**  
```solidity
function releaseTo(address account, uint256 value) external override {
    requestedMints[msg.sender] -= value;
    underlying().safeTransfer(account, value);
}
```

Any address with non-zero `requestedMints[msg.sender]` (i.e., anyone who called `depositFor`) can release underlying tokens to ANY `account`, including themselves or any third party. There is no check that the specified `account` is the intended deposit recipient. While this is an emergency recovery mechanism, it allows depositors to forward underlying tokens to arbitrary addresses without going through the normal confidential token withdrawal process.

**Impact:**  
- A depositor can use `releaseTo` as an untracked transfer of underlying tokens to any address.  
- No confidential token accounting occurs (no CTX, no supply change).  
- If a depositor's intent was to deposit for another account and the callback failed, they can instead redirect the underlying to themselves or any address.

**Recommended fix:**  
Add documentation clearly stating that `releaseTo` is a privileged emergency function only for recovering locked funds after failed callbacks. Optionally, restrict the `account` parameter to either `msg.sender` or the original `account` argument from `depositFor` (tracked in a separate mapping).

**Confidence:** High

---

### F-13 — `requestDecryptHistoricTransfer` Fee Charged Even When Caller Cannot Decrypt

**Severity:** Low  
**Files/functions:** `contracts/ConfidentialToken.sol` — `requestDecryptHistoricTransfer`, `requestDecryptHistoricTransferFor`

**Root cause:**  
The callback fee is charged to `msg.sender` immediately when `requestDecryptHistoricTransferFor` is called. Authorization is only checked inside `_handleHistoricViewRequest` (callback time). If the caller is not a participant in the transfer and has no time-range or transfer-ID authorization from either participant, the callback reverts with `UserIsNotAuthorizedToDecryptTransfer`. The fee is permanently lost.

**Attack or failure scenario:**  
A user submits `requestDecryptHistoricTransfer(anyEncryptedData)` as a test or mistake. The callback fires, the user is not authorized, the fee is consumed.

**Impact:**  
- Fee loss for unauthorized or mistaken decryption requests.  
- No on-chain pre-check for authorization (unlike EIP-3009 where `authorizationState` can be checked first).

**Recommended fix:**  
Add a view function that checks authorization before the CTX is submitted (this exists as `canDecryptHistoricTransfer`). Document clearly in the function NatSpec that the fee is consumed regardless of authorization outcome, and guide users to call `canDecryptHistoricTransfer` first. Alternatively, emit a refund mechanism for failed authorization callbacks.

**Confidence:** High (documented behavior, but UX severity is Low)

---

### F-14 — No Public Key Deregistration: Stale Viewer Keys Are Permanent

**Severity:** Informational  
**Files/functions:** `contracts/ConfidentialToken.sol` — `registerPublicKey`

**Root cause:**  
Once a public key is registered via `registerPublicKey`, it cannot be deregistered:
```solidity
if (!_knownPublicKey(accountAddress)) {
    publicKeys[accountAddress] = publicKey;
    emit PublicKeyRegistered(accountAddress);
}
```

Public keys are permanent. If a viewer's private key is compromised, there is no way to invalidate the registered public key. An attacker who gains access to the viewer's private key can decrypt all future and historic ECIES-encrypted transfers emitted for that viewer.

**Impact:**  
- Compromised viewer keys cannot be rotated on-chain; all future balances will still be encrypted under the compromised key.  
- Users can set a new `viewerAddress` to a new public key (effectively rotating), but the old public key remains registered and usable for `authorizeHistoricViewTransferId`.

**Recommended fix:**  
Allow users to rotate their viewer public key by having `setViewerPublicKey` trigger a balance re-encryption (already partially done) and, for historic-view authorization, make authorization checks use `viewerAddresses[holder]` rather than raw public key addresses. Document the key compromise recovery process.

**Confidence:** High

---

### F-15 — `depositFor(account, value)` Functionally Unusable for Third-Party Deposits

**Severity:** Informational  
**Files/functions:** `contracts/ConfidentialWrapper.sol` — `depositFor`, `_onMint`

**Root cause:**  
As described in F-02, `requestedMints` is tracked for `msg.sender` but `_onMint` checks `requestedMints[account]`. In the normal non-attack case where no one else has deposited for `account`, `requestedMints[account] = 0`, so the callback always fails with `OutdatedMint` for any `depositFor(account, value)` call where `account ≠ msg.sender`.

**Impact:**  
- Third-party deposits (e.g., DEX aggregators, payment processors, or relayers) cannot be used with `ConfidentialWrapper`.  
- The ERC20Wrapper interface implies support for `depositFor(account, value)` with `account ≠ msg.sender`.  
- The behavior is non-obvious and not documented as a limitation.

**Recommended fix:**  
Fix the `requestedMints` tracking as described in F-02, or document that `depositFor` only works when `account == msg.sender` and override the function signature accordingly.

**Confidence:** High

---

## Open Questions for Maintainers

1. **`withdrawTo` account parameter**: Is the design intention that `withdrawTo(account, value)` should release underlying tokens to `account` or to `msg.sender`? If `account` is a parameter, it should be honored. If it's always `msg.sender`, the parameter should be removed to avoid confusion.

2. **`depositFor` for third parties**: Should `depositFor(account, value)` where `account ≠ msg.sender` be supported? If so, how should `requestedMints` be tracked to correctly correlate the depositor's `releaseTo` eligibility with the mint recipient?

3. **Callback fee refund policy**: Should there be any refund or "credit" mechanism when a callback reverts due to authorization failure (e.g., historic decrypt) or insufficient funds for resubmission? The current model makes all fees non-refundable.

4. **Resubmission cap**: Is there a maximum number of CTX resubmissions per transfer? If not, should there be one to prevent unbounded fee drain?

5. **EIP-3009 nonce on callback failure**: Is it acceptable that an EIP-3009 authorization nonce is permanently consumed when the CTX callback reverts? Or should there be a recovery path?

6. **tx.gasprice reliance**: The BITE.md warns about EIP-1559 transactions where `tx.gasprice` resolves differently. Is there a mechanism to ensure only legacy transactions are used for CTX-submitting functions, or is the gas price assumed to always be the configured constant?

7. **Fee-on-transfer underlying tokens**: Is `ConfidentialWrapper` intended to support only standard (non-fee) ERC20 tokens as underlying assets? This should be documented.

8. **Public key deregistration**: Is there a planned mechanism for key compromise recovery? Currently the only mitigation is to change `viewerAddress` but the old key remains registered.

---

## Test Gaps

| Area | Positive | Negative | Async/stale | Auth boundary | Malformed |
|---|---|---|---|---|---|
| Transfer | ✓ covered | Partial (no fee) | ✓ covered | Partial | Missing |
| Encrypted transfer | ✓ covered | Partial | ✓ covered | Missing | Missing |
| Allowance transfer | ✓ covered | ✓ covered | Partial | ✓ covered | Missing |
| EIP3009 | ✓ covered | ✓ covered | Missing | ✓ covered | Missing |
| Mint | ✓ covered | Missing | Missing | Missing | Missing |
| Burn | ✓ covered | Missing | Missing | Missing | Missing |
| Current viewer | ✓ covered | Partial | Missing | Missing | Missing |
| Historic viewer | ✓ covered | ✓ covered | Missing | ✓ covered | Missing |
| Wrapper deposit | Partial (self only) | Missing | Missing | Missing | Missing |
| Wrapper withdrawal | Partial | Missing | Missing | Missing | Missing |

### Critical Missing Tests

**Transfer — Malformed inputs:**
```typescript
it("should reject callback with malformed decrypted argument lengths", async () => {
    // Forge a callback with decryptedArguments[0].length == 16 (not 32 or 0)
    // Assert: DecryptionBadFormat reverted
});
```

**EIP-3009 — Async/stale:**
```typescript
it("nonce is consumed but callback fails: transfer does not occur", async () => {
    // Sign EIP3009 authorization
    // Drain gasPayer's ETH balance
    // Submit authorization: should revert (gasPayer check) → nonce NOT consumed
    // Submit with valid ETH but induce InsufficientBalance in callback
    // Assert: nonce consumed, balance unchanged
});
```

**Mint — Auth boundary:**
```typescript
it("only authorized role can call mint", async () => {
    const [, hacker] = await ethers.getSigners();
    await token.connect(hacker).mint(hacker, 1000n)
        .should.be.reverted;  // AccessManaged restriction
});
```

**Wrapper deposit — Third-party (account != msg.sender):**
```typescript
it("depositFor(bob, amount) by alice fails callback with OutdatedMint", async () => {
    // Alice deposits for Bob
    await token.connect(alice).depositFor(bob, amount);
    await bite.sendCallback().should.be.revertedWithCustomError(token, "OutdatedMint");
    // Verify Alice can releaseTo to recover
    await token.connect(alice).releaseTo(alice, amount);
    expect(await underlyingToken.balanceOf(alice)).to.equal(amount);
});
```

**Wrapper deposit — Front-running griefing:**
```typescript
it("attacker depositFor(victim, N) before victim's CTX causes victim fund loss", async () => {
    // Victim deposits for self
    // Attacker deposits for victim (front-run)
    // Attacker's CTX fires first
    // Victim's CTX fails
    // Victim's underlying is permanently locked (verify with requestedMints)
});
```

**Wrapper withdrawal — account parameter:**
```typescript
it("withdrawTo sends tokens to msg.sender, not account parameter", async () => {
    await token.connect(owner).withdrawTo(bob, amount);
    await bite.sendCallback();
    // Current behavior: owner receives tokens, not bob
    const ownerUnderlying = await underlyingToken.balanceOf(owner);
    const bobUnderlying = await underlyingToken.balanceOf(bob);
    // This test documents the bug: owner gets tokens, bob gets nothing
    expect(ownerUnderlying).to.equal(amount);
    expect(bobUnderlying).to.equal(0n);
});
```

**Historic viewer — Revocation race:**
```typescript
it("fee is lost when holder revokes between request and callback", async () => {
    // Viewer requests decrypt with authorization
    const feeBefore = await token.ethBalanceOf(viewer);
    await token.connect(viewer).requestDecryptHistoricTransfer(encryptedData);
    // Holder revokes before callback
    await token.connect(holder).removeHistoricViewAuth(viewer);
    // Callback reverts
    await bite.sendCallback().should.be.revertedWithCustomError(token, "UserIsNotAuthorizedToDecryptTransfer");
    // Fee is gone
    expect(await token.ethBalanceOf(viewer)).to.equal(feeBefore - callbackFee);
});
```

**callbackFee / tx.gasprice truncation:**
```typescript
it("should revert or warn when callbackFee is less than tx.gasprice", async () => {
    await token.setCallbackFee(1n);  // 1 wei, much less than gasprice
    await token.mint(owner, amount)
        .should.be.revertedWith(...);  // or CTX gets 0 gas and fails silently
});
```

---

## Function Isolation Worksheets

### Phase 1 — HistoricView

**`HistoricView.revokeAll(authStorage, holder, viewer)`**
- Visibility: internal (library)  
- Inputs: holder (controlled by ConfidentialToken caller), viewer (msg.sender-authorized)  
- State writes: sets `fromTimestamp = 0`, `toTimestamp = 0`, clears `transferIds` EnumerableSet  
- Return: `hadPermissions` based on `toTimestamp > 0 || transferIds.length() > 0`  
- Finding: `hadPermissions` check only uses `toTimestamp > 0` — if time range was never set but transfer IDs exist, `hadPermissions = true` is correct. Edge case: if only `fromTimestamp` was set but `toTimestamp = 0` (impossible via `authorizeTimeRange` due to `require(fromTimestamp < toTimestamp)`), this would return `hadPermissions = false`. No vulnerability found.

**`HistoricView._isAuthorized`**
- Checks sender == from || sender == to (participant auto-auth)  
- Checks `fromTimestamp <= timestamp && toTimestamp > timestamp` (inclusive lower, exclusive upper)  
- Checks `transferIds.contains(transferId)` for both from and to  
- Finding: Authorization can be granted by EITHER from OR to side independently. This is the documented behavior. However, a third-party viewer authorized by `to` (recipient) but not `from` (sender) can see the transfer. The sender cannot prevent this once a transfer occurs.

**`HistoricView.decodeIfAuthorized`**
- Called at CALLBACK time (inside onDecrypt)  
- Decodes TransferData from 160-byte decryptedTransferData  
- Calls `_isAuthorized(authStorage, transferData, sender)`  
- Finding: Auth is checked at callback time, not request time (F-05).

### Phase 2 — EIP3009

**`EIP3009._transferWithAuthorization`**
- Checks time window, nonce, signature  
- Marks nonce used, emits AuthorizationUsed, calls `_transfer`  
- `_transfer` overrides OZ ERC20's `_transfer`, which calls `_update`  
- In ConfidentialToken, `_update` submits a CTX  
- Finding: For plain ERC20 `transferWithAuthorization`, the nonce is consumed before CTX fires. If CTX callback fails (InsufficientBalance), nonce is permanently consumed. But this only happens if the initial `_transfer` call doesn't revert, meaning the CTX was successfully submitted. (F-03)

**`cancelAuthorization`**  
- Checks nonce not already used  
- Signature verification against `CANCEL_AUTHORIZATION_TYPEHASH`  
- Sets `_authorizationStates[authorizer][nonce] = true`  
- No vulnerability found.

### Phase 3 — ConfidentialEIP3009

**`ConfidentialEIP3009._transferWithAuthorization`**  
- `bytes value` hashed as `keccak256(value)` in the EIP-712 struct for signing  
- This means the signer signs the hash of the ciphertext, NOT the plaintext  
- A relayer who intercepts the signed message cannot substitute a different ciphertext (it would invalidate the signature)  
- Finding: Correct design — the signer commits to a specific TE ciphertext. The TE ciphertext encodes the transfer amount such that the BITE network decrypts it in the callback.  
- Concern: The signer must provide a correctly formatted TE ciphertext (via `BITE.encryptTE`). An incorrectly formatted ciphertext would pass signature verification but fail the callback length check.

### Phase 4 — ConfidentialToken External

**`onDecrypt`**  
- Authentication: `_callbackSenders.remove(msg.sender)` — one-shot, rejects replays  
- Dispatches on `plaintextArguments[0]` byte  
- Finding: If `plaintextArguments[0]` byte is ≥ 2 (future action), `ActionNotRecognized` reverts. Safe.  
- Finding: The `_callbackSenders` set uses `EnumerableSet.remove` which returns false if not present. The `require` ensures only registered senders can call `onDecrypt`. Correct.

**`setViewerAddress`**  
- `onlyRegisteredUser(viewer)` — viewer must have a registered public key  
- Calls `deposit(msg.sender)` (payable)  
- If viewer changes, submits CTX to re-encrypt balance  
- Finding: Fee deducted per call. Multiple rapid calls to `setViewerAddress` burn multiple fees. No limit.

**`encryptedTransfer` / `encryptedTransferFrom`**  
- `encryptedTransfer`: spender = address(0), gasPayer = msg.sender  
- `encryptedTransferFrom`: spender = msg.sender, gasPayer = msg.sender  
- Both check TE ciphertext length: `encryptedValue.length == BITE.TE_RETURN_SIZE_THRESHOLD + 1`  
- Finding: The length check prevents arbitrary bytes from being passed as encrypted value. Correct.

**`requestDecryptHistoricTransferFor`**  
- Fee deducted upfront  
- `onlyRegisteredUser(historicViewer)` checked at call time  
- Finding: If viewer deregisters... but public keys cannot be deregistered (F-14). Safe.  
- Finding: Auth checked at callback time (F-05).

### Phase 5 — Internal Machinery

**`_handleTransferRequest`**  
- Decodes `TransferInfo` from plaintext args  
- `_validateDecryptedArguments`: ensures correct count (2 for mint/burn, 3 for transfer)  
- Decodes value (last arg), fromBalance, toBalance  
- Spends allowance if spender set (BEFORE staleness check — F-07)  
- Checks `_lastChanged` staleness  
- If stale: emits `CTXResubmitted`, calls `_updateWithGasPayer` (no spender) — allowance consumed, not re-checked  
- If not stale: calls `_decryptedUpdate`  

**`_decryptedUpdate`**  
- Self-transfer: calls `_setBalance(from, fromBalance)` then returns (no supply change)  
- Mint (from=0): `_totalSupply += value`, `_setBalance(to, toBalance + value)`  
- Burn (to=0): checks `fromBalance >= value`, `_totalSupply -= value`, `_setBalance(from, fromBalance - value)`  
- Transfer: checks `fromBalance >= value`, updates both balances  
- All paths call `_onUpdate` which emits events and may call `_onBurn`/`_onMint` in wrapper  

**`_setBalance`**  
- Re-encrypts with TE (updates `_thresholdBalances`)  
- Updates `_lastChanged[holder]` to `block.number`  
- If viewer registered: re-encrypts with ECIES (updates `_userBalances`)  
- Finding: `_setBalance(address(0), ...)` is called for burn (to=address(0)) — this sets `_thresholdBalances[address(0)]` and `_lastChanged[address(0)]`. Harmless (zero address has no private key), but wastes gas.

**`_encryptArguments`**  
- Correctly handles mint (from=0), burn (to=0), transfer (both non-0), self-transfer  
- Finding: For self-transfer (from=to), both fromBalance and toBalance are fetched (same account) — 3 args total. Callback correctly handles via `_validateDecryptedArguments` (3-arg path).

### Phase 6 — MintableConfidentialToken

**`mint(address to, uint256 amount)`**  
- `restricted` modifier: OpenZeppelin AccessManaged — only authorized roles  
- Calls `_mint(to, amount)` → `_update(address(0), to, amount)` → CTX submitted  
- Finding: zero address check: `_mint(to, amount)` in OZ calls `_update(0, to, amount)`. OZ ERC20._update checks `to != 0` but ConfidentialToken overrides `_update` without calling super. The zero address check is NOT performed. `_mint(address(0), amount)` would succeed in submitting a CTX. In the callback, `_decryptedUpdate(address(0), address(0), ...)` would be called which is neither mint nor burn nor transfer — actually `from = address(0)` (mint path) with `to = address(0)`. This would call `_totalSupply += amount` and `_setBalance(address(0), amount)`. Supply inflates without any real holder. LOW severity.

### Phase 7 — ConfidentialWrapper

**`depositFor(account, value)`**  
- `requestedMints[msg.sender] += value`  
- `super.depositFor(account, value)` → OZ ERC20Wrapper → transfers underlying, calls `_mint(account, value)`  
- `_mint` → CTX → callback → `_onMint(account, value)` checks `requestedMints[account]`  
- Finding: F-02 (requestedMints mismatch for account != msg.sender)

**`withdrawTo(account, value)`**  
- Checks `account != address(this)`  
- Calls `_burn(_msgSender(), value)` → CTX → callback → `_onBurn(_msgSender(), value)` → `underlying().safeTransfer(_msgSender(), value)`  
- Finding: F-01 (account parameter ignored)

**`releaseTo(account, value)`**  
- `requestedMints[msg.sender] -= value` (reverts if underflow)  
- `underlying().safeTransfer(account, value)`  
- Finding: No authentication check on `account` (F-12). Anyone with pending requestedMints can release to any address.  
- Finding: Can be used to release tokens to any address without going through confidential token withdrawal. No supply update occurs. If used after a failed callback (where no tokens were minted), this correctly recovers the underlying. If used after a SUCCESSFUL callback (which consumed the target's requestedMints, not the depositor's), this would release underlying without burning confidential tokens — but this cannot happen in the normal flow since `_onMint` uses `requestedMints[to]`, not `requestedMints[msg.sender]`.

