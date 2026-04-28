// SPDX-License-Identifier: AGPL-3.0-only

/**
 *   IConfidentialWrapper.sol - confidential-token
 *   Copyright (C) 2025-Present SKALE Labs
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

pragma solidity ^0.8.27;

import { IConfidentialToken } from "./IConfidentialToken.sol";


/// @title IConfidentialWrapper
/// @author Dmytro Stebaiev
/// @notice Interface of ConfidentialWrapper that adds confidentiality to an ERC20 token
interface IConfidentialWrapper is IConfidentialToken {
    /// @notice Releases the wrapped tokens to the caller
    /// @notice Almost never is used and is required only if callback call fails
    /// @param account The address to release tokens to
    /// @param value The amount of tokens to release
    function releaseTo(address account, uint256 value) external;

    /// @notice Cancels a pending withdrawal initiated by `withdrawTo`
    /// @notice Required only when the burn CTX never
    ///         finalizes (e.g. resubmission chain reverts) and the caller
    ///         needs issue a fresh `withdrawTo`
    /// @dev If the original burn callback later fires, it will revert on
    ///      `OutdatedBurn` and the cnf burn will roll back; the caller's
    ///      cnf balance is preserved
    function cancelWithdrawTo() external;
}
