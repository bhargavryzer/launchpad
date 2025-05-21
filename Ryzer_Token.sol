// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/// @title RyzerToken
/// @notice A non-upgradeable ERC20 token with vesting, timelock, and access control features.
/// @dev Manages token distribution, vesting schedules, and governance with timelock protection.
///      Uses OpenZeppelin's AccessControl for role-based permissions.
contract RyzerToken is ERC20, ReentrancyGuard, AccessControl, ERC165 {
    using SafeERC20 for IERC20;

    // --- Constants ---
    uint256 private constant TOTAL_SUPPLY_CAP = 1_000_000_000e18; // 1 billion tokens
    uint256 private constant PRESALE_ALLOCATION = 30_000_000e18; // 3%
    uint256 private constant PUBLIC_ALLOCATION = 150_000_000e18; // 15%
    uint256 private constant TEAM_ALLOCATION = 100_000_000e18; // 10%
    uint256 private constant STAKING_ALLOCATION = 150_000_000e18; // 15%
    uint256 private constant ECOSYSTEM_ALLOCATION = 200_000_000e18; // 20%
    uint256 private constant TREASURY_ALLOCATION = 140_000_000e18; // 14%
    uint256 private constant MARKETING_ALLOCATION = 100_000_000e18; // 10%
    uint256 private constant DEX_LIQUIDITY_ALLOCATION = 80_000_000e18; // 8%
    uint256 private constant CEX_LIQUIDITY_ALLOCATION = 50_000_000e18; // 5%
    uint48 private constant ONE_MONTH = 90 days;
    uint256 private constant MAX_BATCH_SIZE = 50; // Limits gas consumption in batch operations
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // --- Enums ---
    /// @notice Defines wallet types for token allocation.
    enum WalletType {
        Treasury,
        Team,
        Private,
        Staking,
        Marketing,
        DexLiquidity,
        CexLiquidity
    }

    // --- Structs ---
    /// @notice Stores vesting schedule details for a beneficiary.
    struct VestingSchedule {
        uint128 totalAmount; // Total tokens to vest (after initial unlock)
        uint128 released; // Tokens already released
        uint128 initialUnlock; // Tokens unlocked at TGE
        uint48 startTime; // Start time of vesting
        uint48 duration; // Total duration of vesting in seconds
        uint48 cliff; // Cliff period in seconds
    }

    /// @notice Stores timelock action details.
    struct TimelockAction {
        uint48 scheduledTime; // When the action can be executed
        bool executed; // Whether the action has been executed
        bytes data; // Encoded function call data
    }

    /// @notice Vesting status for view function.
    struct VestingStatus {
        uint256 totalAmount;
        uint256 released;
        uint256 releasable;
        uint256 initialUnlock;
        uint48 startTime;
        uint48 duration;
        uint48 cliff;
    }

    // --- State Variables ---
    uint48 public immutable deploymentTimestamp; // Contract deployment time
    uint48 public timelockDelay; // Delay for timelock actions
    mapping(address beneficiary => VestingSchedule) private _vestingSchedules; // Vesting schedules by beneficiary
    uint256 private _totalVestedAmount; // Total tokens vested
    uint256 private _totalReleasedVestedAmount; // Total vested tokens released
    mapping(bytes32 actionId => TimelockAction) public timelockActions; // Timelock actions by ID
    uint32 private _timelockNonce; // Nonce for timelock action IDs
    uint32 public pendingTimelockActions; // Number of pending timelock actions
    mapping(WalletType walletType => address wallet) public wallets; // Wallet addresses by type
    bool public emergencyPaused; // Emergency pause state

    // --- Events ---
    event TimelockDelayUpdated(
        uint48 indexed oldDelay,
        uint48 indexed newDelay
    );
    event VestingReleased(
        address indexed beneficiary,
        uint256 amount,
        bool completed
    );
    event VestingScheduleCreated(
        address indexed beneficiary,
        uint256 totalAmount,
        uint256 initialUnlock
    );
    event LiquidityLocked(
        address indexed lpToken,
        uint256 amount,
        address indexed lockContract
    );
    event ActionScheduled(
        bytes32 indexed actionId,
        bytes data,
        uint48 scheduledTime
    );
    event ActionExecuted(bytes32 indexed actionId);
    event ActionCanceled(bytes32 indexed actionId);
    event WalletUpdated(
        WalletType indexed walletType,
        address indexed oldWallet,
        address indexed newWallet
    );
    event EmergencyPausedUpdated(bool indexed paused);
    event RoleChanged(
        bytes32 indexed role,
        address indexed account,
        bool granted
    );
    event TokenWithdrawn(
        address indexed token,
        address indexed recipient,
        uint256 amount
    );

    // --- Errors ---
    error InvalidParameter(string parameter);
    error VestingNotActive();
    error CliffNotPassed();
    error NoTokensToRelease();
    error TimelockPending();
    error TimelockNotReady();
    error EmergencyPausedError();
    error BatchSizeExceeded();
    error SupplyCapExceeded();
    error CannotWithdrawNativeToken();
    error InvalidTokenAddress();

    // --- Modifiers ---
    modifier whenNotPaused() {
        if (emergencyPaused) revert EmergencyPausedError();
        _;
    }

    /// @notice Constructor to initialize the contract.
    /// @param treasuryWallet Treasury wallet address.
    /// @param teamWallet Team wallet address.
    /// @param privateWallet Private sale wallet address.
    /// @param stakingWallet Staking wallet address.
    /// @param marketingWallet Marketing wallet address.
    /// @param dexLiquidityWallet DEX liquidity wallet address.
    /// @param cexLiquidityWallet CEX liquidity wallet address.
    /// @param admin Admin address for role management.
    constructor(
        address treasuryWallet,
        address teamWallet,
        address privateWallet,
        address stakingWallet,
        address marketingWallet,
        address dexLiquidityWallet,
        address cexLiquidityWallet,
        address admin
    ) ERC20("RyzerX", "RYZX") {
        if (admin == address(0)) revert InvalidParameter("admin");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        emit RoleChanged(DEFAULT_ADMIN_ROLE, admin, true);
        emit RoleChanged(ADMIN_ROLE, admin, true);
        _initializeWallets(
            treasuryWallet,
            teamWallet,
            privateWallet,
            stakingWallet,
            marketingWallet,
            dexLiquidityWallet,
            cexLiquidityWallet
        );
        _initializeVesting();
        deploymentTimestamp = uint48(block.timestamp);
        timelockDelay = 3 days;
    }

    // --- Admin Functions ---
    /// @notice Updates the timelock delay.
    /// @param newDelay New delay in seconds (1 hour to 30 days).
    function updateTimelockDelay(
        uint48 newDelay
    ) external onlyRole(ADMIN_ROLE) whenNotPaused {
        if (newDelay < 1 hours || newDelay > 30 days) {
            revert InvalidParameter("timelockDelay");
        }
        if (timelockDelay == newDelay) return;
        uint48 oldDelay = timelockDelay;
        timelockDelay = newDelay;
        emit TimelockDelayUpdated(oldDelay, newDelay);
    }

    /// @notice Schedules a liquidity locking action.
    /// @param lpToken LP token address.
    /// @param amount Amount to lock.
    /// @param lockContract Lock contract address.
    function scheduleLockLiquidity(
        address lpToken,
        uint256 amount,
        address lockContract
    ) external onlyRole(ADMIN_ROLE) whenNotPaused {
        if (
            lpToken == address(0) || lockContract == address(0) || amount == 0
        ) {
            revert InvalidParameter("lpToken or lockContract or amount");
        }
        bytes memory data = abi.encodeCall(
            this.executeLockLiquidity,
            (lpToken, amount, lockContract)
        );
        _scheduleTimelockAction(data);
    }

    /// @notice Executes a liquidity locking action after timelock.
    /// @param lpToken LP token address.
    /// @param amount Amount to lock.
    /// @param lockContract Lock contract address.
    function executeLockLiquidity(
        address lpToken,
        uint256 amount,
        address lockContract
    ) external nonReentrant onlyRole(ADMIN_ROLE) whenNotPaused {
        bytes32 actionId = keccak256(
            abi.encode(
                "executeLockLiquidity",
                lpToken,
                amount,
                lockContract,
                _timelockNonce - 1
            )
        );
        _executeTimelockAction(actionId);
        IERC20(lpToken).safeTransfer(lockContract, amount);
        emit LiquidityLocked(lpToken, amount, lockContract);
    }

    /// @notice Withdraws arbitrary tokens sent to the contract.
    /// @param tokenAddress Token address to withdraw.
    /// @param amount Amount to withdraw.
    /// @param recipient Recipient address.
    function withdrawToken(
        address tokenAddress,
        uint256 amount,
        address recipient
    ) external onlyRole(ADMIN_ROLE) whenNotPaused {
        if (tokenAddress == address(0)) revert InvalidTokenAddress();
        if (tokenAddress == address(this)) revert CannotWithdrawNativeToken();
        if (recipient == address(0)) revert InvalidParameter("recipient");
        
        IERC20(tokenAddress).safeTransfer(recipient, amount);
        emit TokenWithdrawn(tokenAddress, recipient, amount);
    }

    /// @notice Cancels a timelock action.
    /// @param actionId Action ID to cancel.
    function cancelTimelockAction(
        bytes32 actionId
    ) external onlyRole(ADMIN_ROLE) whenNotPaused {
        TimelockAction storage action = timelockActions[actionId];
        if (action.scheduledTime == 0 || action.executed) {
            revert InvalidParameter("actionId");
        }
        delete timelockActions[actionId];
        pendingTimelockActions--;
        emit ActionCanceled(actionId);
    }

    /// @notice Updates a wallet address.
    /// @param walletType Wallet type to update.
    /// @param newWallet New wallet address.
    function updateWallet(
        WalletType walletType,
        address newWallet
    ) external onlyRole(ADMIN_ROLE) whenNotPaused {
        if (newWallet == address(0)) revert InvalidParameter("newWallet");
        address oldWallet = wallets[walletType];
        if (oldWallet == newWallet) return;
        wallets[walletType] = newWallet;
        emit WalletUpdated(walletType, oldWallet, newWallet);
    }

    /// @notice Sets the emergency pause state.
    /// @param paused New pause state.
    function setEmergencyPause(bool paused) external onlyRole(ADMIN_ROLE) {
        if (emergencyPaused == paused) return;
        emergencyPaused = paused;
        emit EmergencyPausedUpdated(paused);
    }

    /// @notice Revokes a role from an account.
    /// @param role Role to revoke.
    /// @param account Account to revoke the role from.
    function revokeRoleForAddress(
        bytes32 role,
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (account == address(0)) revert InvalidParameter("account");
        if (!hasRole(role, account)) revert InvalidParameter("role");
        _revokeRole(role, account);
        emit RoleChanged(role, account, false);
    }

    // --- Public Functions ---
    /// @notice Releases vested tokens for a beneficiary.
    /// @param beneficiary Beneficiary address.
    function releaseVestedTokens(
        address beneficiary
    ) external nonReentrant whenNotPaused {
        if (msg.sender != beneficiary && !hasRole(ADMIN_ROLE, msg.sender)) {
            revert InvalidParameter("caller");
        }
        VestingSchedule storage schedule = _vestingSchedules[beneficiary];
        if (schedule.totalAmount == 0) revert VestingNotActive();
        if (block.timestamp < schedule.startTime + schedule.cliff) {
            revert CliffNotPassed();
        }
        uint256 vested = _calculateVested(schedule);
        uint256 releasable;
        unchecked {
            releasable = vested - schedule.released;
        }
        if (releasable == 0) revert NoTokensToRelease();
        schedule.released = uint128(vested);
        _totalReleasedVestedAmount = _totalReleasedVestedAmount + releasable;
        address self = address(this);
        _transfer(self, beneficiary, releasable);
        bool completed = vested >= schedule.totalAmount;
        emit VestingReleased(beneficiary, releasable, completed);
    }

    /// @notice Releases vested tokens for multiple beneficiaries.
    /// @param beneficiaries Array of beneficiary addresses.
    function batchReleaseVestedTokens(
        address[] calldata beneficiaries
    ) external nonReentrant onlyRole(ADMIN_ROLE) whenNotPaused {
        uint256 length = beneficiaries.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        uint256 totalReleasable;
        for (uint256 i = 0; i < length; ) {
            address beneficiary = beneficiaries[i];
            VestingSchedule storage schedule = _vestingSchedules[beneficiary];
            if (
                schedule.totalAmount == 0 ||
                block.timestamp < schedule.startTime + schedule.cliff
            ) {
                unchecked {
                    ++i;
                }
                continue;
            }
            uint256 vested = _calculateVested(schedule);
            uint256 releasable;
            unchecked {
                releasable = vested - schedule.released;
            }
            if (releasable == 0) {
                unchecked {
                    ++i;
                }
                continue;
            }
            schedule.released = uint128(vested);
            totalReleasable += releasable;
            _transfer(address(this), beneficiary, releasable);
            unchecked {
                ++i;
            }
        }
        if (totalReleasable != 0) {
            _totalReleasedVestedAmount =
                _totalReleasedVestedAmount +
                totalReleasable;
            emit VestingReleased(address(0), totalReleasable, false);
        }
    }

    // --- View Functions ---
    /// @notice Gets vesting status for a beneficiary.
    /// @param beneficiary Beneficiary address.
    /// @return status Vesting status struct.
    function getVestingStatus(
        address beneficiary
    ) external view returns (VestingStatus memory status) {
        VestingSchedule storage schedule = _vestingSchedules[beneficiary];
        status.totalAmount = schedule.totalAmount;
        status.released = schedule.released;
        status.initialUnlock = schedule.initialUnlock;
        status.startTime = schedule.startTime;
        status.duration = schedule.duration;
        status.cliff = schedule.cliff;
        if (
            status.totalAmount == 0 ||
            block.timestamp < schedule.startTime + schedule.cliff
        ) {
            status.releasable = 0;
        } else {
            uint256 vested = _calculateVested(schedule);
            status.releasable = vested - status.released;
        }
    }

    /// @notice Gets timelock action details.
    /// @param actionId Action ID.
    /// @return scheduledTime Scheduled execution time.
    /// @return executed Execution status.
    /// @return data Action data.
    function getTimelockAction(
        bytes32 actionId
    )
        external
        view
        returns (uint48 scheduledTime, bool executed, bytes memory data)
    {
        TimelockAction storage action = timelockActions[actionId];
        scheduledTime = action.scheduledTime;
        executed = action.executed;
        data = action.data;
    }

    /// @notice Gets total vested amount.
    /// @return Total vested amount.
    function totalVested() external view returns (uint256) {
        return _totalVestedAmount;
    }

    /// @notice Gets total released vested amount.
    /// @return Total released vested amount.
    function totalVestedReleased() external view returns (uint256) {
        return _totalReleasedVestedAmount;
    }

    // --- Internal Functions ---
    /// @notice Initializes wallet addresses.
    /// @param treasuryWallet Treasury wallet address.
    /// @param teamWallet Team wallet address.
    /// @param privateWallet Private sale wallet address.
    /// @param stakingWallet Staking wallet address.
    /// @param marketingWallet Marketing wallet address.
    /// @param dexLiquidityWallet DEX liquidity wallet address.
    /// @param cexLiquidityWallet CEX liquidity wallet address.
    function _initializeWallets(
        address treasuryWallet,
        address teamWallet,
        address privateWallet,
        address stakingWallet,
        address marketingWallet,
        address dexLiquidityWallet,
        address cexLiquidityWallet
    ) private {
        if (
            treasuryWallet == address(0) ||
            teamWallet == address(0) ||
            privateWallet == address(0) ||
            stakingWallet == address(0) ||
            marketingWallet == address(0) ||
            dexLiquidityWallet == address(0) ||
            cexLiquidityWallet == address(0)
        ) revert InvalidParameter("wallet");
        wallets[WalletType.Treasury] = treasuryWallet;
        wallets[WalletType.Team] = teamWallet;
        wallets[WalletType.Private] = privateWallet;
        wallets[WalletType.Staking] = stakingWallet;
        wallets[WalletType.Marketing] = marketingWallet;
        wallets[WalletType.DexLiquidity] = dexLiquidityWallet;
        wallets[WalletType.CexLiquidity] = cexLiquidityWallet;
    }

    /// @notice Initializes vesting schedules for token allocations.
    function _initializeVesting() private {
        // Private Sale (PreSale): 3%, 50% TGE, 4-month cliff, 12-month vesting
        _setupVesting(
            wallets[WalletType.Private],
            PRESALE_ALLOCATION,
            (PRESALE_ALLOCATION * 50) / 100, // 50% TGE unlock
            4 * ONE_MONTH,
            12 * ONE_MONTH
        );
        // Public: 15%, 25% TGE, no cliff, 12-month vesting
        _setupVesting(
            wallets[WalletType.Treasury], // Public tokens managed by Treasury wallet
            PUBLIC_ALLOCATION,
            (PUBLIC_ALLOCATION * 25) / 100, // 25% TGE unlock
            0,
            12 * ONE_MONTH
        );
        // Team: 10%, 0% TGE, 12-month cliff, 36-month vesting
        _setupVesting(
            wallets[WalletType.Team],
            TEAM_ALLOCATION,
            0,
            12 * ONE_MONTH,
            36 * ONE_MONTH
        );
        // Staking: 15%, 0% TGE, no cliff, 48-month vesting
        _setupVesting(
            wallets[WalletType.Staking],
            STAKING_ALLOCATION,
            0,
            0,
            48 * ONE_MONTH
        );
        // Ecosystem: 20%, 0% TGE, 12-month cliff, 36-month vesting
        _setupVesting(
            wallets[WalletType.Treasury],
            ECOSYSTEM_ALLOCATION,
            0,
            12 * ONE_MONTH,
            36 * ONE_MONTH
        );
        // Treasury: 14%, 0% TGE, 12-month cliff, 36-month vesting
        _setupVesting(
            wallets[WalletType.Treasury],
            TREASURY_ALLOCATION,
            0,
            12 * ONE_MONTH,
            36 * ONE_MONTH
        );
        // Marketing: 10%, 0% TGE, 12-month cliff, 36-month vesting
        _setupVesting(
            wallets[WalletType.Marketing],
            MARKETING_ALLOCATION,
            0,
            12 * ONE_MONTH,
            36 * ONE_MONTH
        );
        // DEX Liquidity: 8%, 100% TGE, no vesting
        _mint(wallets[WalletType.DexLiquidity], DEX_LIQUIDITY_ALLOCATION);
        // CEX Liquidity: 5%, 100% TGE, no vesting
        _mint(wallets[WalletType.CexLiquidity], CEX_LIQUIDITY_ALLOCATION);
        if (totalSupply() > TOTAL_SUPPLY_CAP) revert SupplyCapExceeded();
    }

    /// @notice Sets up a vesting schedule for a beneficiary.
    /// @param beneficiary Beneficiary address.
    /// @param amount Total amount to vest.
    /// @param initialUnlockAmount Initial unlock amount.
    /// @param cliff Cliff period in seconds.
    /// @param duration Total vesting duration in seconds.
    function _setupVesting(
        address beneficiary,
        uint256 amount,
        uint256 initialUnlockAmount,
        uint48 cliff,
        uint48 duration
    ) private {
        if (
            amount == 0 ||
            initialUnlockAmount > amount ||
            duration == 0 ||
            cliff >= duration
        ) {
            revert InvalidParameter("vesting parameters");
        }
        uint128 vestingAmount = uint128(amount - initialUnlockAmount);
        uint48 startTime = uint48(block.timestamp);
        address self = address(this);
        if (vestingAmount != 0) {
            VestingSchedule storage schedule = _vestingSchedules[beneficiary];
            schedule.totalAmount = vestingAmount;
            schedule.startTime = startTime;
            schedule.duration = duration;
            schedule.cliff = cliff;
            schedule.initialUnlock = uint128(initialUnlockAmount);
            _totalVestedAmount = _totalVestedAmount + vestingAmount;
            _mint(self, vestingAmount);
        }
        if (initialUnlockAmount != 0) {
            _mint(beneficiary, initialUnlockAmount);
        }
        emit VestingScheduleCreated(
            beneficiary,
            vestingAmount,
            initialUnlockAmount
        );
    }

    /// @notice Schedules a timelock action.
    /// @param data Encoded function call data.
    function _scheduleTimelockAction(bytes memory data) private {
        bytes32 actionId = keccak256(
            abi.encode(data, _timelockNonce, block.timestamp)
        );
        if (timelockActions[actionId].scheduledTime != 0) {
            revert TimelockPending();
        }
        uint48 scheduledTime = uint48(block.timestamp) + timelockDelay;
        TimelockAction storage action = timelockActions[actionId];
        action.scheduledTime = scheduledTime;
        action.executed = false;
        action.data = data;
        pendingTimelockActions++;
        _timelockNonce++;
        emit ActionScheduled(actionId, data, scheduledTime);
    }

    /// @notice Executes a timelock action.
    /// @param actionId Action ID to execute.
    function _executeTimelockAction(bytes32 actionId) private {
        TimelockAction storage action = timelockActions[actionId];
        if (action.scheduledTime == 0 || action.executed) {
            revert InvalidParameter("actionId");
        }
        if (block.timestamp < action.scheduledTime) revert TimelockNotReady();
        action.executed = true;
        pendingTimelockActions--;
        emit ActionExecuted(actionId);
    }

    /// @notice Calculates vested amount for a schedule.
    /// @param schedule Vesting schedule.
    /// @return Vested amount.
    function _calculateVested(
        VestingSchedule storage schedule
    ) private view returns (uint256) {
        if (block.timestamp >= schedule.startTime + schedule.duration) {
            return schedule.totalAmount;
        }
        if (block.timestamp < schedule.startTime + schedule.cliff) {
            return schedule.released;
        }
        uint48 elapsed = uint48(block.timestamp) - schedule.startTime;
        uint48 vestingPeriod = schedule.duration - schedule.cliff;
        uint256 vested = (schedule.totalAmount * (elapsed - schedule.cliff)) /
            vestingPeriod;
        
        // Ensure we don't lose precision on final release
        if (block.timestamp >= schedule.startTime + schedule.duration) {
            return schedule.totalAmount;
        }
        
        return vested;
    }

    /// @notice Returns true if the contract supports the specified interface.
    function supportsInterface(bytes4 interfaceId) public view override(ERC165, AccessControl) returns (bool) {
        return interfaceId == type(IERC20).interfaceId ||
               interfaceId == type(AccessControl).interfaceId ||
               interfaceId == type(ERC165).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}