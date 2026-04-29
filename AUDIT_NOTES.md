# Audit Working Notes

## Files Read
- BITE.md (agent-docs) — full read
- README.md — full read
- contracts/ConfidentialToken.sol — full read
- contracts/ConfidentialWrapper.sol — full read
- contracts/MintableConfidentialToken.sol — full read
- contracts/HistoricView.sol — full read
- contracts/eip3009/EIP3009.sol — full read
- contracts/eip3009/ConfidentialEIP3009.sol — full read
- contracts/eip3009/EIP712Utils.sol — full read
- contracts/errors.sol — full read
- contracts/interfaces/IConfidentialToken.sol — full read
- contracts/interfaces/IConfidentialWrapper.sol — full read
- test/ConfidentialToken.ts — partial (lines 1-950)
- test/ConfidentialWrapper.ts — full read
- test/EIP3009.ts — lines 1-100
- test/ConfidentialEIP3009.ts — lines 1-150
- test/tools/helpers.ts, fixtures.ts — full read
- hardhat.config.ts, package.json — full read

## Key Invariants
1. _thresholdBalances[holder] = TE-encrypted balance used for CTX math
2. _userBalances[holder] = ECIES-encrypted balance for off-chain viewing
3. _totalSupply tracks total tokens
4. 1:1 backing in ConfidentialWrapper (underlying == confidential tokens)
5. _lastChanged[holder] tracks block of last balance update for staleness detection
6. _callbackSenders set tracks authorized CTX callbacks (one-shot auth)
7. requestedMints[depositor] tracks pending deposits in wrapper

## Critical Code Paths Traced

### Transfer flow
1. transfer(to, value) → _update(from, to, value) → _updateWithGasPayer(from, to, msg.sender, value)
2. _updateWithGasPayer → encryptTE(value) → _encryptedUpdate(from, to, spender=0, gasPayer, encryptedValue)
3. _encryptedUpdate: deduct fee from _ethBalance[gasPayer], encryptArguments, submitCTX, add ctxSender to _callbackSenders, send fee to ctxSender
4. BITE callback → onDecrypt → _handleTransferRequest
5. _handleTransferRequest: spendAllowance (if spender), check staleness, _decryptedUpdate or resubmit
6. _decryptedUpdate: update _totalSupply, _setBalance, _onUpdate
7. _setBalance: re-encrypt balance with TE, update _lastChanged, re-encrypt with ECIES for viewer

### Mint flow (MintableConfidentialToken)
1. mint(to, amount) → _mint(to, amount) → _update(address(0), to, amount)
2. Same as transfer but from=address(0), no fromBalance decrypted

### Burn flow
1. burn(amount) → _burn(msg.sender, amount) → _update(msg.sender, address(0), amount)
2. Same as transfer but to=address(0), no toBalance decrypted

### ConfidentialWrapper deposit
1. depositFor(account, value) → requestedMints[msg.sender] += value → super.depositFor(account, value)
2. super.depositFor → safeTransferFrom(underlying, msg.sender→wrapper) → _mint(account, value)
3. _mint(account, value) → _update(0, account, value) → async CTX submitted
4. CTX callback → _handleTransferRequest → _decryptedUpdate → _onUpdate → _onMint(account, value)
5. _onMint: requestedMints[account] -= value (!!!! uses account, not msg.sender)

### ConfidentialWrapper withdrawal
1. withdrawTo(account, value) → _burn(msgSender, value)
2. _burn → async CTX submitted
3. CTX callback → _decryptedUpdate → _onUpdate → _onBurn(from=msgSender, value)
4. _onBurn: safeTransfer(underlying, from=msgSender, value) (!!!! ignores account parameter)

## Findings Summary

### CRITICAL/HIGH
1. `withdrawTo(account, value)` ignores `account` — underlying always sent to burner (msgSender), not specified account. HIGH.
2. `depositFor(account, value)` requestedMints tracking mismatch — requestedMints[msg.sender] incremented but _onMint checks requestedMints[account]. For account!=msg.sender, attacker can front-run victim's deposit to steal funds. HIGH.

### MEDIUM
3. Fee loss when `_encryptedUpdate` fails during resubmission — allowance check in _handleTransferRequest fires before staleness check, if resubmit callback fails state is reverted but fee already consumed. MEDIUM.
4. Integer truncation in `callbackFee / tx.gasprice` — if tx.gasprice > callbackFee, gas limit = 0. MEDIUM.
5. Historic view fee charged before authorization verified at callback time — fee consumed if holder revokes auth between request and callback. MEDIUM.
6. EIP-3009 nonce consumed before CTX finality — if callback fails for any reason after nonce is marked used, authorization is permanently burned. MEDIUM.
7. Unbounded resubmission loop in stale state — each resubmission consumes another fee from gasPayer with no cap. MEDIUM.

### LOW
8. `_isValidPublicKey` accepts degenerate keys — the check uses OR instead of AND, so a key where only one coordinate is zero passes validation, but such points are not valid on secp256k1. LOW.
9. ERC20 Transfer event not emitted (shadow issue) — custom Transfer(from, to) overrides ERC20 Transfer(from, to, uint256). LOW.
10. No access control on `releaseTo` for arbitrary account destination — anyone who has deposited can redirect their locked tokens to any address. LOW.
11. Solidity 0.8.30 with evmVersion istanbul — using newer Solidity features with an older EVM target could generate invalid opcodes for some features. LOW.

### INFORMATIONAL
12. `depositFor(account, value)` functionally broken for account != msg.sender in normal scenarios. INFO.
13. No public key deregistration path — once registered, public keys are permanent. INFO.
14. Historic view authorization revocation race condition between time-range grant and decryption request. INFO.
15. `balanceOf` always reverts — breaks ERC20 interface, tools that call balanceOf will fail. INFO.
16. ECIES-encrypted balance leaks viewer-changed events. INFO.

