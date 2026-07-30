// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// A stand-in for a DeFi-style target contract an agent might call. No real funds, test-only.
contract MockTarget {
    uint256 public pings;
    uint256 public received;
    address public lastRecipient;

    event Swapped(address recipient, uint256 amountIn);

    function ping() external {
        pings++;
    }

    function pay() external payable {
        received += msg.value;
    }

    /// Recipient is the 4th argument, so a scope policy sets recipientArgIndex[swap] = 4.
    function swap(address, address, uint256 amountIn, address recipient) external payable {
        lastRecipient = recipient;
        received += msg.value;
        emit Swapped(recipient, amountIn);
    }

    /// An out-of-scope selector, deliberately never allowlisted in the tests.
    function drain(address) external {
        pings++;
    }

    receive() external payable {}
}
