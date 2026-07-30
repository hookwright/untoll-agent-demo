// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title SessionKeyDelegate
/// @notice The EIP-7702 session-key delegate for the UNTOLL agent lane. BUILD 1, containment core.
///
/// The agent's LLM can be jailbroken; this contract is the boundary that holds when it is. Its scope
/// lives in storage set once at install, not in a signature the model can be tricked into producing:
/// a target allowlist, a selector allowlist, a per-transaction and per-epoch value cap (lazy-reset
/// counter), a hard expiry, and a per-selector recipient policy so an in-scope swap cannot redirect
/// its output to an attacker. A session key operates strictly inside that scope. The owner (the EOA
/// itself, under 7702) is unrestricted.
///
/// Two entry points, on purpose:
///   - execute(...)    hard-reverts with a legible custom error on any breach. This is the
///                     containment guarantee: the drain does not move funds, full stop.
///   - tryExecute(...) does NOT revert on a breach. It emits ScopeViolation and returns false without
///                     forwarding, so the breach is recorded on chain (an event on a reverting call is
///                     discarded by the EVM, so containment-by-revert alone cannot leave a trace).
///                     This is the measurable signal a later unit reads to estimate p_slash.
///
/// BUILD 1 arms no slasher, prices no bond, and pays no reward. It only contains.
contract SessionKeyDelegate {
    // ---------------------------------------------------------------------
    // Errors. Legible, so a reverted call reads as a scope code and never as out-of-gas.
    // ---------------------------------------------------------------------
    error NotInitialized();
    error AlreadyInitialized();
    error NotOwner();
    error NotSessionKey();
    error TargetNotAllowed(address target);
    error SelectorNotAllowed(bytes4 selector);
    error PerTxCapExceeded(uint256 value, uint256 cap);
    error PerEpochCapExceeded(uint256 spent, uint256 value, uint256 cap);
    error Expired(uint256 nowTs, uint256 expiry);
    error RecipientNotAllowed(address recipient);
    error CalldataTooShort();
    error CallReverted();

    // Reason tags carried by ScopeViolation and returned by probe(). One per breach class.
    bytes4 internal constant R_OK        = 0x00000000;
    bytes4 internal constant R_TARGET    = bytes4(keccak256("TARGET"));
    bytes4 internal constant R_SELECTOR  = bytes4(keccak256("SELECTOR"));
    bytes4 internal constant R_PER_TX    = bytes4(keccak256("PER_TX"));
    bytes4 internal constant R_PER_EPOCH = bytes4(keccak256("PER_EPOCH"));
    bytes4 internal constant R_EXPIRED   = bytes4(keccak256("EXPIRED"));
    bytes4 internal constant R_RECIPIENT = bytes4(keccak256("RECIPIENT"));
    bytes4 internal constant R_SHORT     = bytes4(keccak256("CALLDATA_SHORT"));

    // ---------------------------------------------------------------------
    // Events.
    // ---------------------------------------------------------------------
    event Initialized(address indexed owner, address indexed sessionKey, uint64 expiry);
    event ScopedCall(address indexed target, uint256 value, bytes4 selector);
    /// Emitted only by tryExecute, only on a breach, and it is the on-chain violation trace.
    event ScopeViolation(address indexed target, bytes4 indexed selector, bytes4 reason);

    // ---------------------------------------------------------------------
    // Scope, set once at install. Under 7702 this lives in the agent EOA's own storage.
    // ---------------------------------------------------------------------
    address public owner;
    address public sessionKey;
    uint64 public expiry;
    uint128 public perTxCap;
    uint128 public perEpochCap;
    uint64 public epochLength;
    uint64 public epochStart;
    uint128 public epochSpent;
    bool public initialized;

    mapping(address => bool) public allowedTarget;
    mapping(bytes4 => bool) public allowedSelector;
    mapping(address => bool) public allowedRecipient;
    /// 1-based argument index of the recipient for a selector; 0 means no recipient policy.
    /// e.g. swap(address,address,uint256,address) sets the 4th arg, so recipientArgIndex = 4.
    mapping(bytes4 => uint256) public recipientArgIndex;

    struct Scope {
        address owner;
        address sessionKey;
        uint64 expiry;
        uint128 perTxCap;
        uint128 perEpochCap;
        uint64 epochLength;
        address[] targets;
        bytes4[] selectors;
        address[] recipients;
        bytes4[] recipientSelectors; // parallel to recipientArgs
        uint256[] recipientArgs;
    }

    // ---------------------------------------------------------------------
    // Install. One time. Owner-gated so a session key can never widen its own scope.
    // ---------------------------------------------------------------------
    function initialize(Scope calldata s) external {
        if (initialized) revert AlreadyInitialized();
        // Under 7702, address(this) is the agent EOA; only that EOA (the owner) installs its scope.
        if (msg.sender != s.owner) revert NotOwner();

        owner = s.owner;
        sessionKey = s.sessionKey;
        expiry = s.expiry;
        perTxCap = s.perTxCap;
        perEpochCap = s.perEpochCap;
        epochLength = s.epochLength;
        epochStart = uint64(block.timestamp);
        epochSpent = 0;

        for (uint256 i = 0; i < s.targets.length; i++) allowedTarget[s.targets[i]] = true;
        for (uint256 i = 0; i < s.selectors.length; i++) allowedSelector[s.selectors[i]] = true;
        for (uint256 i = 0; i < s.recipients.length; i++) allowedRecipient[s.recipients[i]] = true;
        for (uint256 i = 0; i < s.recipientSelectors.length; i++) {
            recipientArgIndex[s.recipientSelectors[i]] = s.recipientArgs[i];
        }

        initialized = true;
        emit Initialized(s.owner, s.sessionKey, s.expiry);
    }

    // ---------------------------------------------------------------------
    // The hard-revert containment path. A session key acts only inside scope; any breach reverts.
    // ---------------------------------------------------------------------
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory ret)
    {
        if (!initialized) revert NotInitialized();
        if (msg.sender != sessionKey) revert NotSessionKey();

        bytes4 reason = _checkAndAccount(target, value, data);
        if (reason != R_OK) _revertFor(reason, target, value, data);

        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) revert CallReverted();
        emit ScopedCall(target, value, _selectorOf(data));
    }

    // ---------------------------------------------------------------------
    // The non-reverting monitor path. On a breach it records ScopeViolation and forwards nothing,
    // so the funds are equally safe and the attempt is measurable on chain. On a pass it forwards.
    // ---------------------------------------------------------------------
    function tryExecute(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bool ok, bytes4 reason, bytes memory ret)
    {
        if (!initialized) revert NotInitialized();
        if (msg.sender != sessionKey) revert NotSessionKey();

        reason = _checkAndAccount(target, value, data);
        if (reason != R_OK) {
            emit ScopeViolation(target, _selectorOf(data), reason);
            return (false, reason, "");
        }

        (ok, ret) = target.call{value: value}(data);
        if (ok) emit ScopedCall(target, value, _selectorOf(data));
        return (ok, R_OK, ret);
    }

    // ---------------------------------------------------------------------
    // Read-only scope check. No state change, no forward. For a caller that wants to know why first.
    // ---------------------------------------------------------------------
    function probe(address target, uint256 value, bytes calldata data)
        external
        view
        returns (bool ok, bytes4 reason)
    {
        if (block.timestamp > expiry) return (false, R_EXPIRED);
        reason = _check(target, value, data, epochSpent);
        return (reason == R_OK, reason);
    }

    // ---------------------------------------------------------------------
    // Internal: scope check plus epoch accounting. Mutates epochStart/epochSpent on the accepted path.
    // ---------------------------------------------------------------------
    function _checkAndAccount(address target, uint256 value, bytes calldata data)
        internal
        returns (bytes4)
    {
        if (block.timestamp > expiry) return R_EXPIRED;

        // Lazy epoch reset: the first accepted spend after the window rolls the counter.
        uint128 spent = epochSpent;
        if (block.timestamp >= uint256(epochStart) + epochLength) {
            epochStart = uint64(block.timestamp);
            spent = 0;
        }

        bytes4 reason = _check(target, value, data, spent);
        if (reason != R_OK) return reason;

        epochSpent = spent + uint128(value);
        return R_OK;
    }

    /// Pure scope logic against a supplied running total, so probe() and execute() agree exactly.
    function _check(address target, uint256 value, bytes calldata data, uint128 spent)
        internal
        view
        returns (bytes4)
    {
        if (!allowedTarget[target]) return R_TARGET;

        bytes4 sel = _selectorOf(data);
        if (!allowedSelector[sel]) return R_SELECTOR;

        if (value > perTxCap) return R_PER_TX;
        if (uint256(spent) + value > perEpochCap) return R_PER_EPOCH;

        uint256 argIndex = recipientArgIndex[sel];
        if (argIndex != 0) {
            (bool okLen, address recipient) = _recipientAt(data, argIndex);
            if (!okLen) return R_SHORT;
            if (!allowedRecipient[recipient]) return R_RECIPIENT;
        }
        return R_OK;
    }

    function _selectorOf(bytes calldata data) internal pure returns (bytes4) {
        if (data.length < 4) return bytes4(0);
        return bytes4(data[0:4]);
    }

    /// Extract the address argument at a 1-based ABI word index, guarding calldata length.
    function _recipientAt(bytes calldata data, uint256 argIndex)
        internal
        pure
        returns (bool ok, address recipient)
    {
        uint256 wordStart = 4 + 32 * (argIndex - 1);
        if (data.length < wordStart + 32) return (false, address(0));
        uint256 word = uint256(bytes32(data[wordStart:wordStart + 32]));
        return (true, address(uint160(word)));
    }

    function _revertFor(bytes4 reason, address target, uint256 value, bytes calldata data)
        internal
        view
    {
        if (reason == R_TARGET) revert TargetNotAllowed(target);
        if (reason == R_SELECTOR) revert SelectorNotAllowed(_selectorOf(data));
        if (reason == R_PER_TX) revert PerTxCapExceeded(value, perTxCap);
        if (reason == R_PER_EPOCH) revert PerEpochCapExceeded(epochSpent, value, perEpochCap);
        if (reason == R_EXPIRED) revert Expired(block.timestamp, expiry);
        if (reason == R_SHORT) revert CalldataTooShort();
        // R_RECIPIENT
        (, address recipient) = _recipientAt(data, recipientArgIndex[_selectorOf(data)]);
        revert RecipientNotAllowed(recipient);
    }

    receive() external payable {}
}
