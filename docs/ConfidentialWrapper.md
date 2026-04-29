# Solidity API

## ConfidentialWrapper

Confidential wrapper that adds confidentiality to an ERC20 token

### PendingBurn

```solidity
struct PendingBurn {
  address recipient;
  uint256 value;
}
```

### requestedMints

Amount of tokens requested to be wrapped

```solidity
mapping(address => uint256) requestedMints
```

**dev:** _Almost always equals to zero
Has non-zero value only before the callback call is made_

### pendingBurns

Pending burn initiated by `withdrawTo`, awaiting CTX to finalize

```solidity
mapping(address => struct ConfidentialWrapper.PendingBurn) pendingBurns
```

**dev:** _`value` is non-zero only between `withdrawTo` and its `_onBurn` callback
At most one pending withdraw per `from` is allowed; this is what
     lets the recipient survive across the async CTX boundary without
     threading data through `ConfidentialToken`_

### OutdatedMint

```solidity
error OutdatedMint(address to, uint256 value)
```

### OutdatedBurn

```solidity
error OutdatedBurn(address from, uint256 value)
```

### WithdrawalPending

```solidity
error WithdrawalPending(address from)
```

### NoPendingWithdrawal

```solidity
error NoPendingWithdrawal(address from)
```

### constructor

```solidity
constructor(contract IERC20Metadata underlyingToken, string version_, address initialAuthority) public
```

### releaseTo

Releases the wrapped tokens to the caller
Almost never is used and is required only if callback call fails

```solidity
function releaseTo(address account, uint256 value) external
```

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| account | address | The address to release tokens to |
| value | uint256 | The amount of tokens to release |

### cancelWithdrawTo

Cancels a pending withdrawal initiated by `withdrawTo`
Required only when the burn CTX never
        finalizes (e.g. resubmission chain reverts) and the caller
        needs issue a fresh `withdrawTo`

```solidity
function cancelWithdrawTo() external
```

**dev:** _If the original burn callback later fires, it will revert on
     `OutdatedBurn` and the cnf burn will roll back; the caller's
     cnf balance is preserved_

### transferFrom

Transfers `value` tokens from `from` to `to` using allowance mechanism.

```solidity
function transferFrom(address from, address to, uint256 value) public virtual returns (bool result)
```

**dev:** _This function call may return true and revert on callback producing no changes_

#### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| from | address | Address to transfer tokens from |
| to | address | Address to transfer tokens to |
| value | uint256 | Amount of tokens to be transferred |

#### Return Values

| Name | Type | Description |
| ---- | ---- | ----------- |
| result | bool | Always returns true |

### depositFor

```solidity
function depositFor(address account, uint256 value) public returns (bool success)
```

**dev:** _Allow a user to deposit underlying tokens and mint the corresponding number of wrapped tokens._

### withdrawTo

```solidity
function withdrawTo(address account, uint256 value) public returns (bool success)
```

**dev:** _Allow a user to burn a number of wrapped tokens and withdraw the corresponding number of underlying tokens._

### decimals

```solidity
function decimals() public view returns (uint8 decimalsValue)
```

### totalSupply

```solidity
function totalSupply() public view returns (uint256 supply)
```

**dev:** _Returns the value of tokens in existence._

### balanceOf

```solidity
function balanceOf(address account) public pure returns (uint256 balance)
```

**dev:** _Returns the value of tokens owned by `account`._

### _burnTo

```solidity
function _burnTo(address from, address to, uint256 value) internal
```

### _onUpdate

```solidity
function _onUpdate(address from, address to, uint256 value) internal
```

### _update

```solidity
function _update(address from, address to, uint256 value) internal
```

