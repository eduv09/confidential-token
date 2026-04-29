# Solidity API

## IConfidentialWrapper

Interface of ConfidentialWrapper that adds confidentiality to an ERC20 token

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

