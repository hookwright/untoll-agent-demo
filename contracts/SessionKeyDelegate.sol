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
    // TKT-0433. The allowance lane.
    error UnitPerTxCapExceeded(uint256 amount, uint256 cap);
    error UnitPerEpochCapExceeded(uint256 spent, uint256 amount, uint256 cap);
    error AllowanceSelectorUnmetered(bytes4 selector);
    error AmountPolicyMalformed();
    error NotSelf();
    // TKT-0459. The ledger bound and the named sweep.
    error GrantLimitReached(uint256 limit);
    error ArrayLengthMismatch();
    // TKT-0457. A zero-length epoch is not a window.
    error EpochLengthZero();

    // Reason tags carried by ScopeViolation and returned by probe(). One per breach class.
    bytes4 internal constant R_OK        = 0x00000000;
    bytes4 internal constant R_TARGET    = bytes4(keccak256("TARGET"));
    bytes4 internal constant R_SELECTOR  = bytes4(keccak256("SELECTOR"));
    bytes4 internal constant R_PER_TX    = bytes4(keccak256("PER_TX"));
    bytes4 internal constant R_PER_EPOCH = bytes4(keccak256("PER_EPOCH"));
    bytes4 internal constant R_EXPIRED   = bytes4(keccak256("EXPIRED"));
    bytes4 internal constant R_RECIPIENT = bytes4(keccak256("RECIPIENT"));
    bytes4 internal constant R_SHORT     = bytes4(keccak256("CALLDATA_SHORT"));
    bytes4 internal constant R_UNIT_TX    = bytes4(keccak256("UNIT_PER_TX"));
    bytes4 internal constant R_UNIT_EPOCH = bytes4(keccak256("UNIT_PER_EPOCH"));
    bytes4 internal constant R_GRANT_LIMIT = bytes4(keccak256("GRANT_LIMIT"));

    // The ERC-20 shapes that GRANT a standing allowance. Deliberately a short, explicit list
    // rather than a heuristic: these are the calls whose effect OUTLIVES this contract, because
    // the allowance is a row in the token's storage and nothing here can reach it later.
    // approve(address,uint256)
    bytes4 internal constant SEL_APPROVE = 0x095ea7b3;
    // increaseAllowance(address,uint256)
    bytes4 internal constant SEL_INC_ALLOWANCE = 0x39509351;
    // Both put the spender at ABI word 1 and the amount at word 2. A token with a non-standard
    // allowance function is OUTSIDE this list and outside the sweep, which is a stated limit and
    // not an oversight: such a target should not be in an agent allowlist.
    uint256 internal constant ALLOWANCE_SPENDER_ARG = 1;

    // ---------------------------------------------------------------------
    // Events.
    // ---------------------------------------------------------------------
    event Initialized(address indexed owner, address indexed sessionKey, uint64 expiry);
    event ScopedCall(address indexed target, uint256 value, bytes4 selector);
    /// Emitted only by tryExecute, only on a breach, and it is the on-chain violation trace.
    event ScopeViolation(address indexed target, bytes4 indexed selector, bytes4 reason);
    /// TKT-0433. Emitted when a scoped call grants a standing allowance, so the grant is on chain
    /// and in this contract's own ledger rather than only in the token's storage.
    event AllowanceGranted(address indexed token, address indexed spender, uint256 amount);
    event AllowanceSwept(address indexed token, address indexed spender, bool ok);
    event Revoked(uint256 swept, uint256 remaining);

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

    // TKT-0433, the token-amount lane. `perTxCap`/`perEpochCap` meter the NATIVE value field, and
    // an ERC-20 call carries value == 0, so they bound nothing at all on a token market. These
    // meter the decoded amount ARGUMENT for any selector that declares where its amount lives.
    // Units are the token's own units and ONE counter is shared across every metered target: two
    // tokens of different decimals therefore over-count against each other, which errs toward
    // refusing. That is the safe direction for a containment contract and it is a stated limit.
    uint256 public perTxUnitCap;
    uint256 public perEpochUnitCap;
    uint256 public unitSpent;
    /// 1-based ABI word index of the uint256 amount for a selector; 0 means no amount policy.
    mapping(bytes4 => uint256) public amountArgIndex;

    /// The standing-allowance ledger. Every allowance this delegate grants is recorded here so
    /// revokeAndSweep() can zero it. Without this, killing the agent leaves the allowance alive.
    struct Grant {
        address token;
        address spender;
    }

    Grant[] public grants;

    /// TKT-0459. THE LEDGER IS STRUCTURALLY BOUNDED, AND THAT IS THE POINT OF THE NUMBER.
    ///
    /// `revokeAndSweep` walks this array, so its worst case is the array length. Left unbounded,
    /// the length is chosen by whoever can make grant calls, which during an incident is the
    /// attacker: 300 decoy approves measured EXACTLY ZERO against both budgets, because the unit
    /// caps meter summed AMOUNT and never COUNT, and a 1-wei grant is nearly free against an
    /// amount cap no matter how the caps are set. So amount metering cannot bound count, and only
    /// a structural bound can. This is not a policy the installer signs, it is the constant that
    /// makes the panic button cost a known number of steps instead of an attacker-chosen one.
    ///
    /// RESIDUAL, NAMED: a jailbroken key can still fill the ledger and deny the legitimate lane
    /// NEW spenders until the owner sweeps. That is availability, it is bounded, and it clears in
    /// one transaction. Re-approving a spender already on the books is never refused, so a full
    /// ledger cannot stop an agent adjusting a grant it already holds.
    uint256 public constant MAX_GRANTS = 64;

    /// 1-based position of (token, spender) in `grants`; 0 means no row. ONE structure holds this
    /// fact. The boolean it replaced was a second copy of the same truth, and TKT-0439 is the
    /// record of what two structures holding one fact cost here.
    mapping(address => mapping(address => uint256)) public grantIndex;

    /// Whether this delegate carries a standing-allowance row for (token, spender). Derived, so
    /// the external read surface is unchanged while the storage behind it is single-source.
    function granted(address token, address spender) public view returns (bool) {
        return grantIndex[token][spender] != 0;
    }

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
        uint256 perTxUnitCap;
        uint256 perEpochUnitCap;
        uint64 epochLength;
        address[] targets;
        bytes4[] selectors;
        address[] recipients;
        bytes4[] recipientSelectors; // parallel to recipientArgs
        uint256[] recipientArgs;
        bytes4[] amountSelectors; // parallel to amountArgs
        uint256[] amountArgs;
    }

    // ---------------------------------------------------------------------
    // Install. One time. Owner-gated so a session key can never widen its own scope.
    //
    // The gate is `address(this)`, and it has to be. Under 7702 the delegate's code runs AT the
    // agent EOA, so the owner IS the account and an install is that account calling itself.
    // Gating on a field of the caller-supplied `Scope` instead is no gate at all: the caller
    // chooses that field in the same call, so anyone satisfies it by naming themselves. That was
    // the shape of this check until 2026-08-20. Because `delegate()` and `installScope()` are two
    // separate transactions, the window between them was a front-run that took the account
    // permanently, since there is no re-initialize. See test/InitializeAuth.t.sol.
    //
    // `s.owner` is kept and asserted rather than dropped: it is the caller's statement of intent,
    // it is what `Initialized` carries, and a scope built against the wrong account is refused
    // rather than silently rewritten.
    // ---------------------------------------------------------------------
    function initialize(Scope calldata s) external {
        if (initialized) revert AlreadyInitialized();
        if (msg.sender != address(this)) revert NotOwner();
        if (s.owner != address(this)) revert NotOwner();

        // TKT-0457. A ZERO-LENGTH EPOCH IS NOT A WINDOW, AND IT VOIDS BOTH PER-EPOCH CAPS.
        //
        // `_epochRolled()` is `block.timestamp >= epochStart + epochLength`, which at length 0 is
        // UNCONDITIONALLY TRUE, so every call rolls the window and clears both counters before any
        // check reads them. Measured before this guard: 20 ether left under a 2 ether per-epoch
        // cap IN A SINGLE BLOCK, 20 of 20 spends accepted.
        //
        // It is the same fail-open that a code mutation simulates, reached through CONFIGURATION
        // instead, and that is worse rather than milder: it needs no code change and leaves this
        // file looking correct, so nobody finds it by reading. One of the four clients guarded it,
        // in TypeScript, and a direct call to this function bypasses all four. A guard that lives
        // in one of four clients is not a guard.
        //
        // Same shape as the allowance refusal below: the contract does not choose the number, it
        // refuses to be installed without a real one.
        if (s.epochLength == 0) revert EpochLengthZero();

        owner = address(this);
        sessionKey = s.sessionKey;
        expiry = s.expiry;
        perTxCap = s.perTxCap;
        perEpochCap = s.perEpochCap;
        perTxUnitCap = s.perTxUnitCap;
        perEpochUnitCap = s.perEpochUnitCap;
        epochLength = s.epochLength;
        epochStart = uint64(block.timestamp);
        epochSpent = 0;
        unitSpent = 0;

        if (s.recipientSelectors.length != s.recipientArgs.length) revert AmountPolicyMalformed();
        if (s.amountSelectors.length != s.amountArgs.length) revert AmountPolicyMalformed();

        for (uint256 i = 0; i < s.targets.length; i++) allowedTarget[s.targets[i]] = true;
        for (uint256 i = 0; i < s.selectors.length; i++) allowedSelector[s.selectors[i]] = true;
        for (uint256 i = 0; i < s.recipients.length; i++) allowedRecipient[s.recipients[i]] = true;
        for (uint256 i = 0; i < s.recipientSelectors.length; i++) {
            recipientArgIndex[s.recipientSelectors[i]] = s.recipientArgs[i];
        }
        for (uint256 i = 0; i < s.amountSelectors.length; i++) {
            if (s.amountArgs[i] == 0) revert AmountPolicyMalformed();
            amountArgIndex[s.amountSelectors[i]] = s.amountArgs[i];
        }

        // TKT-0433. AN ALLOWANCE-GRANTING SELECTOR MAY NOT BE INSTALLED UNMETERED.
        //
        // This is the install-time half of the fix and it is the half that matters, because the
        // hole was never that the caps were computed wrongly. It was that a call which grants a
        // PERMANENT right could pass a scope check that only ever looked at the native value
        // field, and so cost exactly zero. An unbounded approve is not a large spend, it is an
        // unbounded one, and it outlives both this contract expiring and this contract being
        // revoked.
        //
        // The contract does not choose the policy here. It refuses to be installed WITHOUT one,
        // which leaves the number to the installer and removes the silent default of infinity.
        for (uint256 i = 0; i < s.selectors.length; i++) {
            bytes4 sel = s.selectors[i];
            if (sel != SEL_APPROVE && sel != SEL_INC_ALLOWANCE) continue;
            if (amountArgIndex[sel] == 0 || perTxUnitCap == 0 || perEpochUnitCap == 0) {
                revert AllowanceSelectorUnmetered(sel);
            }
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

        (bytes4 reason,) = _checkAndAccount(target, value, data);
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

        Charge memory c;
        (reason, c) = _checkAndAccount(target, value, data);
        if (reason != R_OK) {
            emit ScopeViolation(target, _selectorOf(data), reason);
            return (false, reason, "");
        }

        (ok, ret) = target.call{value: value}(data);
        if (ok) {
            emit ScopedCall(target, value, _selectorOf(data));
        } else {
            // TKT-0458. The scope passed and the target still moved nothing, so the budget comes
            // back. execute() has always behaved this way, because CallReverted unwinds the
            // charge along with everything else. This is tryExecute agreeing with it, instead of
            // charging the principal for a call that did not happen. Written down as correct
            // behaviour until now, it was TKT-0439 through a different door: an in-scope failure
            // starved the legitimate lane for the rest of the window.
            _uncharge(c);
        }
        return (ok, R_OK, ret);
    }

    // ---------------------------------------------------------------------
    // Read-only scope check. No state change, no forward. For a caller that wants to know why first.
    //
    // TKT-0439. It applies the SAME lazy roll as the write path, as a pure computation over the
    // stored counters. Reading epochSpent/unitSpent raw made probe() refuse PER_EPOCH across a
    // window boundary for a call that execute() would have accepted, and the reference agent loop
    // probes and drops, so a false refusal there manufactures refusals the contract allowed. The
    // roll predicate is shared with _checkAndAccount through _epochRolled() on purpose: two copies
    // of one boundary condition is how these two paths drifted apart in the first place.
    // ---------------------------------------------------------------------
    function probe(address target, uint256 value, bytes calldata data)
        external
        view
        returns (bool ok, bytes4 reason)
    {
        if (block.timestamp > expiry) return (false, R_EXPIRED);
        bool rolled = _epochRolled();
        reason = _check(target, value, data, rolled ? 0 : epochSpent, rolled ? 0 : unitSpent);
        return (reason == R_OK, reason);
    }

    /// True when the live window has elapsed, so the next accounted call rolls it. ONE definition,
    /// read by both the view path and the write path.
    function _epochRolled() internal view returns (bool) {
        return block.timestamp >= uint256(epochStart) + epochLength;
    }

    // ---------------------------------------------------------------------
    // Internal: scope check plus epoch accounting. Mutates epochStart/epochSpent on the accepted path.
    // ---------------------------------------------------------------------
    /// TKT-0458. What a single accepted call actually cost, so `tryExecute` can give it back when
    /// the forward fails. It is RETURNED rather than recomputed at the call site, because whether
    /// a grant row was pushed cannot be recovered after the fact: `_newGrantOf` answers false once
    /// the index is set, so a recomputation would leave the phantom row behind.
    struct Charge {
        uint256 value;
        uint256 units;
        bool grantPushed;
        address token;
        address spender;
    }

    function _checkAndAccount(address target, uint256 value, bytes calldata data)
        internal
        returns (bytes4, Charge memory c)
    {
        if (block.timestamp > expiry) return (R_EXPIRED, c);

        // TKT-0439. THE LAZY EPOCH ROLL IS COMMITTED TO STORAGE ATOMICALLY, BEFORE ANY CHECK CAN
        // RETURN, AND THE LOCALS ARE READ BACK OUT OF STORAGE RATHER THAN KEPT ALONGSIDE IT.
        //
        // THE INVARIANT: epochStart never advances without BOTH counters clearing, on ANY path,
        // reverting or returning.
        //
        // What it was: the advance went to STORAGE and the two zeroes went to LOCALS, and the only
        // writes to the storage counters sat below the early return. execute() reverts on a breach
        // so the EVM unwound the half-applied window, which is why this read as safe. tryExecute()
        // RETURNS, so the advance committed with the counters left at their exhausted values. The
        // window restarted while the budget stayed spent, and every further refusal ate the next
        // window too. A jailbroken session key that can produce nothing but out-of-scope calls
        // could therefore starve the legitimate lane of its whole per-epoch budget forever,
        // because a refusal cost it nothing.
        //
        // Reading the locals back out of storage is the load-bearing half rather than a style
        // choice: it deletes the parallel local/storage pair, so there is no state in which the
        // two can disagree and no later return can leave a window half applied. The unit counter
        // clears with the value counter or the two windows drift apart, and the one nobody
        // watches is the one that stops binding.
        //
        // It is close to free. epochLength, epochStart and epochSpent share storage slot 3
        // (verified with forge inspect ... storage), so advancing the window and clearing the
        // value counter is ONE slot write. Only unitSpent (slot 7) adds a store, and only on the
        // branch that actually rolls.
        //
        // Rolling on a REFUSED call is correct rather than merely safe. The window is a function
        // of TIME, so an eager implementation would have rolled at the boundary with no call at
        // all, and committing here is what makes the lazy form observationally equal to that. It
        // widens nothing: epochStart already advanced on a refused tryExecute before this change,
        // so the timeline is untouched and only the counters are repaired.
        // TKT-0457. THE ROLL LANDS ON THE TRUE BOUNDARY, NOT ON THE ARRIVAL TIME.
        //
        // This used to be `epochStart = uint64(block.timestamp)`, which restarted the window
        // wherever the first caller after the boundary happened to show up, so every gap pushed
        // every later boundary forward by the length of that gap. It could never be used to delay
        // a reset, because a roll always clears the counters, so it hands the agent a fresh budget
        // rather than taking one. What it did break is the paragraph directly above: with a
        // drifting start the lazy form was NOT observationally equal to an eager one that fires at
        // the boundary with no call at all. It is now.
        //
        // The division is safe because `initialize` refuses `epochLength == 0`, and the two
        // repairs are one repair: without that refusal this line would divide by zero, and
        // without this line that refusal would still leave a window that walks.
        if (_epochRolled()) {
            uint64 nowTs = uint64(block.timestamp);
            epochStart = nowTs - ((nowTs - epochStart) % epochLength);
            epochSpent = 0;
            unitSpent = 0;
        }
        uint128 spent = epochSpent;
        uint256 units = unitSpent;

        bytes4 reason = _check(target, value, data, spent, units);
        if (reason != R_OK) return (reason, c);

        epochSpent = spent + uint128(value);
        c.value = value;
        bytes4 sel = _selectorOf(data);
        uint256 amount = 0;
        if (amountArgIndex[sel] != 0) {
            (, amount) = _amountAt(data, amountArgIndex[sel]);
            unitSpent = units + amount;
            c.units = amount;
        } else {
            unitSpent = units;
        }

        // Record any standing allowance this call is about to create, so revokeAndSweep() can
        // reach it later. The token storage is the only other place that fact exists, and this
        // contract has no way to enumerate that.
        if (sel == SEL_APPROVE || sel == SEL_INC_ALLOWANCE) _recordGrant(target, sel, data, amount, c);
        return (R_OK, c);
    }

    /// Split out of `_checkAndAccount` for stack room, and it earns the split: the caller frame
    /// was one local over the limit once the charge had to be carried out of it. `c` is a memory
    /// struct, so it is passed by reference and the flags written here are the ones the caller
    /// returns.
    function _recordGrant(
        address target,
        bytes4 sel,
        bytes calldata data,
        uint256 amount,
        Charge memory c
    ) internal {
        (bool okSp, bool isNew, address spender) = _newGrantOf(target, sel, data);
        if (!okSp) return;
        // The pair is recorded whether or not a row was pushed, so that `grantPushed` is the ONLY
        // thing deciding whether the refund removes one. Leaving these fields zero when nothing
        // was pushed let a mapping lookup in `_uncharge` do the deciding instead, and a guard
        // whose work is being done by a later guard cannot be tested at all: deleting it changed
        // nothing and the mutation survived. Two guards, one outcome, is the same tell as two
        // guards, one reason code.
        c.token = target;
        c.spender = spender;
        if (isNew) {
            grants.push(Grant({token: target, spender: spender}));
            grantIndex[target][spender] = grants.length; // 1-based
            c.grantPushed = true;
        }
        emit AllowanceGranted(target, spender, amount);
    }

    /// TKT-0458. Give back exactly what `_checkAndAccount` took, when the forward moved nothing.
    ///
    /// THE ORDER IS THE DESIGN. The charge has to land BEFORE the forward or a reentrant call
    /// would read an uncharged budget and spend it twice, so the charge stays where it is and is
    /// undone on the failure path instead of being deferred to it.
    ///
    /// It cannot underflow, and that is a consequence of the same order rather than an
    /// assumption. A subcall that reverts unwinds every state change it made, including anything
    /// a nested call had charged, so at this point the counters hold exactly what this frame
    /// wrote. The window cannot have rolled in between either: `block.timestamp` is fixed inside
    /// a transaction, and the roll above has already landed `epochStart` on the boundary that
    /// contains it. And a nested call is not reachable from the target in the first place,
    /// because both entry points require msg.sender to be the session key.
    ///
    /// A row that was PUSHED comes back off, because a grant that reverted created no allowance
    /// and a phantom row is a lie in the ledger the panic button reads. A row that already
    /// existed is left alone: that allowance is still live, and forgetting it would be the
    /// TKT-0454 defect arriving from the other direction.
    function _uncharge(Charge memory c) internal {
        epochSpent = uint128(uint256(epochSpent) - c.value);
        unitSpent = unitSpent - c.units;
        if (c.grantPushed) _removeGrantAt(grantIndex[c.token][c.spender] - 1);
    }

    /// TKT-0459. Does this call create a NEW standing-allowance row, and for whom?
    ///
    /// ONE definition, read by the scope check that enforces MAX_GRANTS and by the accounting
    /// path that pushes the row. If those two ever answered differently, the contract would
    /// refuse a call it was not about to record, or record one it had not counted, and that is
    /// the same drift `_epochRolled()` exists to prevent on the epoch boundary.
    ///
    /// A ZERO-AMOUNT GRANT IS NOT A STANDING ALLOWANCE. `approve(spender, 0)` leaves nothing
    /// behind and `increaseAllowance(spender, 0)` changes nothing, so neither earns a row. That
    /// single fact is what made 300 decoys free: fresh spenders defeated the (token, spender)
    /// dedupe while amount 0 defeated both caps, so the attacker could pick the length of the
    /// array the panic button has to walk.
    ///
    /// A zero approve deliberately does NOT remove an existing row either. The row would have to
    /// come off before the call is forwarded, and on the tryExecute path a forward that then
    /// fails would leave the ledger claiming a revocation that never happened, which is exactly
    /// the lie TKT-0454 was filed for. The sweep re-zeroing an already-zero allowance is cheap;
    /// a ledger that has forgotten a live allowance is not.
    function _newGrantOf(address target, bytes4 sel, bytes calldata data)
        internal
        view
        returns (bool haveSpender, bool isNew, address spender)
    {
        if (sel != SEL_APPROVE && sel != SEL_INC_ALLOWANCE) return (false, false, address(0));
        (haveSpender, spender) = _recipientAt(data, ALLOWANCE_SPENDER_ARG);
        if (!haveSpender) return (false, false, address(0));

        uint256 amtIndex = amountArgIndex[sel];
        // Unreachable while the install-time refusal stands, and handled rather than assumed:
        // with no amount policy this cannot tell a grant from a revocation, so it records.
        if (amtIndex == 0) return (true, grantIndex[target][spender] == 0, spender);

        (bool okAmt, uint256 amount) = _amountAt(data, amtIndex);
        if (!okAmt || amount == 0) return (true, false, spender);
        return (true, grantIndex[target][spender] == 0, spender);
    }

    /// Pure scope logic against a supplied running total. Both entry points feed it a total that
    /// has already had the lazy roll applied (TKT-0439), so probe() and the write path agree on
    /// every scope condition including across a window boundary. probe() still cannot speak to
    /// whether the forwarded call itself will succeed, which is downstream of scope.
    function _check(address target, uint256 value, bytes calldata data, uint128 spent, uint256 units)
        internal
        view
        returns (bytes4)
    {
        if (!allowedTarget[target]) return R_TARGET;

        bytes4 sel = _selectorOf(data);
        if (!allowedSelector[sel]) return R_SELECTOR;

        if (value > perTxCap) return R_PER_TX;
        if (uint256(spent) + value > perEpochCap) return R_PER_EPOCH;

        // The amount lane. Written as two subtractions rather than one addition on purpose: the
        // attacker natural first move is type(uint256).max, and `units + amount` would then
        // revert with an arithmetic panic instead of returning a legible scope code.
        uint256 amtIndex = amountArgIndex[sel];
        if (amtIndex != 0) {
            (bool okAmt, uint256 amount) = _amountAt(data, amtIndex);
            if (!okAmt) return R_SHORT;
            if (amount > perTxUnitCap) return R_UNIT_TX;
            if (amount > perEpochUnitCap || units > perEpochUnitCap - amount) return R_UNIT_EPOCH;
        }

        uint256 argIndex = recipientArgIndex[sel];
        if (argIndex != 0) {
            (bool okLen, address recipient) = _recipientAt(data, argIndex);
            if (!okLen) return R_SHORT;
            if (!allowedRecipient[recipient]) return R_RECIPIENT;
        }

        // TKT-0459. The ledger bound, checked LAST so every more informative scope code wins
        // first. It fires only for a call that would push a NEW row, which is why it shares one
        // definition with the accounting path instead of re-deriving the condition here.
        (, bool isNew,) = _newGrantOf(target, sel, data);
        if (isNew && grants.length >= MAX_GRANTS) return R_GRANT_LIMIT;

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

    /// Extract the uint256 argument at a 1-based ABI word index, guarding calldata length.
    function _amountAt(bytes calldata data, uint256 argIndex)
        internal
        pure
        returns (bool ok, uint256 amount)
    {
        uint256 wordStart = 4 + 32 * (argIndex - 1);
        if (data.length < wordStart + 32) return (false, 0);
        return (true, uint256(bytes32(data[wordStart:wordStart + 32])));
    }

    // ---------------------------------------------------------------------
    // TKT-0433. THE KILL THAT ACTUALLY KILLS.
    //
    // Expiry and the client 7702 re-authorization to the zero address both end this contract
    // ability to act, and NEITHER touches an allowance, because the allowance is a row in the
    // token storage and this contract is not the token. Proven by execution in
    // test/AllowanceOutlivesRevocation.t.sol before this function existed.
    //
    // ORDERING IS LOAD-BEARING AND IT IS THE CALLER JOB: sweep FIRST, re-delegate to zero
    // SECOND. Re-delegating first removes the code that would have done the sweeping, and the
    // allowances are then unreachable by this account forever.
    //
    // `maxSteps` bounds the loop so a long ledger cannot make the panic button run out of gas.
    // Call again while `remaining` is non-zero.
    //
    // TKT-0454. THE REPORT IS PART OF THE KILL, AND IT USED TO BE A LIE.
    //
    // What it was: `(bool ok,) = g.token.call(...)` captured the flag, emitted it, and never READ
    // it. The row was popped and `granted[][]` cleared BEFORE the call, `swept` counted attempts
    // rather than successes, and `remaining` came off `grants.length`, so the function returned
    // (swept 1, remaining 0) over an allowance that was still live and destroyed the only record
    // of what needed retrying in the same transaction. Proven by execution, two ways:
    //
    //   a token that REVERTS on approve (paused, blacklisted, hostile): the flag was false and was
    //   thrown away, and the attacker completed transferFrom for the full amount afterwards;
    //
    //   a token that returns FALSE without reverting, which is ERC-20 to the letter: the low-level
    //   call SUCCEEDS, so the discarded flag was true and `AllowanceSwept` emitted ok=true. There
    //   was no revert, no error and no on-chain trace of the failure anywhere. That variant is why
    //   reading the return value is mandatory rather than tidy: nothing downstream could catch it.
    //
    // SO THE RULE IS NOW: a row leaves the ledger only on a PROVEN zero. `swept` counts proven
    // zeroes, `remaining` counts real survivors, and a survivor keeps its row so the retry exists.
    // A non-zero `remaining` after a full pass means allowances are still live, which is exactly
    // the fact an operator is entitled to during a panic.
    //
    // RESIDUAL, NAMED RATHER THAN HIDDEN: a token that burns all the gas forwarded to `approve`
    // can still make a sweep transaction fail outright, and because survivors keep their place at
    // the top of the ledger, a plain retry meets the same row first.
    // ---------------------------------------------------------------------
    function revokeAndSweep(uint256 maxSteps) external returns (uint256 swept, uint256 remaining) {
        if (!initialized) revert NotInitialized();
        if (msg.sender != address(this)) revert NotSelf();

        // Kill the key first, so nothing can grant a new allowance while the sweep is running.
        expiry = 0;
        sessionKey = address(0);

        // Walk from the END so a removal never moves a row that has not been visited yet: a
        // swap-and-pop at index i can only bring a row DOWN from above i, and everything above i
        // has already been visited by construction.
        uint256 i = grants.length;
        uint256 budget = maxSteps;
        while (i > 0 && budget > 0) {
            unchecked {
                i--;
                budget--;
            }
            Grant memory g = grants[i];
            bool ok = _approveZeroSucceeded(g.token, g.spender);
            emit AllowanceSwept(g.token, g.spender, ok);
            if (ok) {
                _removeGrantAt(i);
                unchecked {
                    swept++;
                }
            }
        }
        remaining = grants.length;
        emit Revoked(swept, remaining);
    }

    /// TKT-0454. Zero an allowance and report whether it is PROVABLY zero afterwards.
    ///
    /// The safe-transfer shape: the call succeeded AND (it returned nothing OR it returned a
    /// non-zero word). Each branch earns its place.
    ///
    ///   `!ok` is the reverting token. False.
    ///
    ///   Empty returndata is USDT and the pre-finalisation ERC-20 tail, which return nothing at
    ///   all. TRUE, and it has to be, or the panic button would report a permanent failure over a
    ///   token it had just zeroed and the operator would retry forever. This deliberately does NOT
    ///   mirror the code-size check a safe-TRANSFER helper makes, because the two directions are
    ///   not symmetric: an approve into a codeless address grants nothing, so no allowance can
    ///   exist there to survive, while refusing the row would strand it with no way to clear it.
    ///
    ///   A returned word is read as a raw non-zero rather than through `abi.decode(ret, (bool))`,
    ///   because that decoder REVERTS on a non-canonical bool, and one hostile token returning
    ///   dirty bits would then brick the panic button for every other grant in the ledger.
    ///
    /// It cannot revert. That is a requirement rather than a property: this runs inside the one
    /// function an operator reaches for when something has already gone wrong.
    function _approveZeroSucceeded(address token, address spender) internal returns (bool) {
        (bool ok, bytes memory ret) =
            token.call(abi.encodeWithSelector(SEL_APPROVE, spender, uint256(0)));
        if (!ok) return false;
        if (ret.length == 0) return true;
        if (ret.length < 32) return false;
        uint256 word;
        assembly {
            word := mload(add(ret, 0x20))
        }
        return word != 0;
    }

    /// TKT-0459. THE OWNER PICKS THE ORDER, NOT THE ATTACKER.
    ///
    /// `revokeAndSweep` walks the ledger LIFO, so the row an attacker pushed most recently is the
    /// row the panic button reaches first. Decoy grants were free, so the ORDER was the attacker's
    /// to choose and the owner needed however many transactions the attacker decided on to reach
    /// the one grant that mattered. This is the direct answer: name the token and spender, and the
    /// sweep goes straight there.
    ///
    /// It is also the answer to the gas residual on `revokeAndSweep`. A token that burns all the
    /// gas forwarded to `approve` sits at the top of the ledger and a plain retry meets it first
    /// forever; naming a different pair steps around it.
    ///
    /// A pair that is NOT on the books is still zeroed, because an operator in an incident may
    /// know about an allowance this delegate never recorded, and the calldata is fixed to
    /// approve(spender, 0), so this opens no arbitrary-call surface. It is not counted in
    /// `swept`, which stays exactly what it is on the other path: LEDGER ROWS PROVEN ZERO.
    function revokeAndSweepNamed(address[] calldata tokens, address[] calldata spenders)
        external
        returns (uint256 swept, uint256 remaining)
    {
        if (!initialized) revert NotInitialized();
        if (msg.sender != address(this)) revert NotSelf();
        if (tokens.length != spenders.length) revert ArrayLengthMismatch();

        // Kill the key first, exactly as the full sweep does. This is a panic lever, not routine
        // hygiene, and a sweep that left the key alive would race the thing it is sweeping.
        expiry = 0;
        sessionKey = address(0);

        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 idx = grantIndex[tokens[i]][spenders[i]];
            bool ok = _approveZeroSucceeded(tokens[i], spenders[i]);
            emit AllowanceSwept(tokens[i], spenders[i], ok);
            if (ok && idx != 0) {
                _removeGrantAt(idx - 1);
                unchecked {
                    swept++;
                }
            }
        }
        remaining = grants.length;
        emit Revoked(swept, remaining);
    }

    /// Drop one row from the ledger. Swap-and-pop, so removal is O(1) and the array stays dense.
    /// The moved row carries its index with it: a stale `grantIndex` would make the named sweep
    /// zero the wrong row, which is a worse failure than not finding one.
    function _removeGrantAt(uint256 i) internal {
        Grant memory g = grants[i];
        grantIndex[g.token][g.spender] = 0;
        uint256 last = grants.length - 1;
        if (i != last) {
            Grant memory moved = grants[last];
            grants[i] = moved;
            grantIndex[moved.token][moved.spender] = i + 1; // 1-based
        }
        grants.pop();
    }

    /// How many standing allowances this delegate still has on its books.
    function grantCount() external view returns (uint256) {
        return grants.length;
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
        if (reason == R_UNIT_TX) {
            (, uint256 amount) = _amountAt(data, amountArgIndex[_selectorOf(data)]);
            revert UnitPerTxCapExceeded(amount, perTxUnitCap);
        }
        if (reason == R_UNIT_EPOCH) {
            (, uint256 amount) = _amountAt(data, amountArgIndex[_selectorOf(data)]);
            revert UnitPerEpochCapExceeded(unitSpent, amount, perEpochUnitCap);
        }
        if (reason == R_GRANT_LIMIT) revert GrantLimitReached(MAX_GRANTS);
        // R_RECIPIENT
        (, address recipient) = _recipientAt(data, recipientArgIndex[_selectorOf(data)]);
        revert RecipientNotAllowed(recipient);
    }

    receive() external payable {}
}
