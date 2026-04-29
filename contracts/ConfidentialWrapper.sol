// SPDX-License-Identifier: AGPL-3.0-only

/**
 *   ConfidentialWrapper.sol - confidential-token
 *   Copyright (C) 2026-Present SKALE Labs
 *   @author Dmytro Stebaiev
 *
 *   confidential-token is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published
 *   by the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   confidential-token is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with confidential-token.  If not, see <https://www.gnu.org/licenses/>.
 */

// cspell:words IERC20

pragma solidity ^0.8.27;

import { ERC20, IERC20 }  from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { ERC20Wrapper }   from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Wrapper.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 }      from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Math }           from "@openzeppelin/contracts/utils/math/Math.sol";

import { ConfidentialToken }    from "./ConfidentialToken.sol";
import { IConfidentialWrapper } from "./interfaces/IConfidentialWrapper.sol";


/// @title ConfidentialWrapper
/// @author Dmytro Stebaiev
/// @notice Confidential wrapper that adds confidentiality to an ERC20 token
contract ConfidentialWrapper is ConfidentialToken, ERC20Wrapper, IConfidentialWrapper {
    using SafeERC20 for IERC20;

    struct PendingBurn {
        address recipient;
        uint256 value;
    }

    /// @notice Amount of tokens requested to be wrapped
    /// @dev Almost always equals to zero
    /// @dev Has non-zero value only before the callback call is made
    mapping (address holder => uint256 value) public requestedMints;

    /// @notice Pending burn initiated by `withdrawTo`, awaiting CTX to finalize
    /// @dev `value` is non-zero only between `withdrawTo` and its `_onBurn` callback
    /// @dev At most one pending withdraw per `from` is allowed; this is what
    ///      lets the recipient survive across the async CTX boundary without
    ///      threading data through `ConfidentialToken`
    mapping (address holder => PendingBurn pending) public pendingBurns;

    error OutdatedMint(address to, uint256 value);
    error OutdatedBurn(address from, uint256 value);
    error WithdrawalPending(address from);
    error NoPendingWithdrawal(address from);

    constructor(
        IERC20Metadata underlyingToken,
        string memory version_,
        address initialAuthority
    )
        ConfidentialToken(
            string.concat("Confidential ", underlyingToken.name()),
            string.concat("cnf", underlyingToken.symbol()),
            version_,
            initialAuthority
        )
        ERC20Wrapper(underlyingToken)
    {}

    // External functions

    /// @inheritdoc IConfidentialWrapper
    function releaseTo(address account, uint256 value) external override {
        requestedMints[msg.sender] -= value;
        underlying().safeTransfer(account, value);
    }

    /// @inheritdoc IConfidentialWrapper
    function cancelWithdrawTo() external override {
        PendingBurn storage pending = pendingBurns[msg.sender];
        require(pending.value != 0, NoPendingWithdrawal(msg.sender));
        delete pendingBurns[msg.sender];
    }

    // Public functions

    ///@inheritdoc ConfidentialToken
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public virtual override(ConfidentialToken, ERC20) returns (bool result) {
        return ConfidentialToken.transferFrom(from, to, value);
    }

    /// @inheritdoc ERC20Wrapper
    function depositFor(address account, uint256 value) public override returns (bool success) {
        requestedMints[msg.sender] += value;
        return super.depositFor(account, value);
    }

    /// @inheritdoc ERC20Wrapper
    function withdrawTo(address account, uint256 value) public override returns (bool success) {
        if (account == address(this)) {
            revert ERC20InvalidReceiver(account);
        }
        _burnTo(_msgSender(), account, value);
        return true;
    }

    /// @inheritdoc ERC20Wrapper
    function decimals() public view override(ERC20, ERC20Wrapper) returns (uint8 decimalsValue) {
        return ERC20Wrapper.decimals();
    }

    /// @inheritdoc ConfidentialToken
    function totalSupply() public view override(ConfidentialToken, ERC20) returns (uint256 supply) {
        return ConfidentialToken.totalSupply();
    }

    /// @inheritdoc ConfidentialToken
    function balanceOf(address account) public pure override(ConfidentialToken, ERC20) returns (uint256 balance) {
        return ConfidentialToken.balanceOf(account);
    }

    // Internal functions

    function _burnTo(address from, address to, uint256 value) internal {
        PendingBurn storage pending = pendingBurns[from];
        require(pending.value == 0, WithdrawalPending(from));
        pending.recipient = to;
        pending.value = value;
        _burn(from, value);
    }

    function _onUpdate(address from, address to, uint256 value) internal override {
        ConfidentialToken._onUpdate(from, to, value);
        if (from == address(0)) {
            _onMint(to, value);
        }
        if (to == address(0)) {
            _onBurn(from, value);
        }
    }

    function _update(address from, address to, uint256 value) internal override(ConfidentialToken, ERC20) {
        ConfidentialToken._update(from, to, value);
    }

    // Private functions

    function _onMint(address to, uint256 value) private {
        bool previouslyRequested;
        (previouslyRequested, requestedMints[to]) = Math.trySub(
            requestedMints[to],
            value
        );
        require(previouslyRequested, OutdatedMint(to, value));
    }

    function _onBurn(address from, uint256 value) private {
        PendingBurn memory pending = pendingBurns[from];
        require(pending.value == value, OutdatedBurn(from, value));
        delete pendingBurns[from];
        underlying().safeTransfer(pending.recipient, value);
    }
}
