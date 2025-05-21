// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title RyzerPublicSale
/// @notice Manages the Public sale with Merkle-based whitelisting, vesting, and timelock-protected actions.
/// @dev Non-upgradeable ERC20 token sale contract with role-based access control.
contract RyzerPublicSale is ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;
    using MerkleProof for bytes32[];

    // --- Constants ---
    uint256 private constant PUBLIC_ALLOCATION = 150_000_000e18; // 150M tokens (15%)
    uint256 private constant TOKEN_PRICE = 0.05 ether; // 0.05 ETH per token
    uint256 private constant MIN_CONTRIBUTION = 0.01 ether; // 0.01 ETH minimum
    uint256 private constant MAX_CONTRIBUTION = 5 ether; // 5 ETH per transaction
    uint256 private constant MAX_USER_CONTRIBUTION = 10 ether; // 10 ETH per user
    uint256 private constant SALE_CAP = 20_000 ether; // 20,000 ETH total cap
    uint48 private constant ONE_HOUR = 1 hours;
    uint48 private constant THIRTY_DAYS = 30 days;
    uint256 private constant TGE_UNLOCK_PERCENT = 25; // 25% TGE unlock
    uint256 private constant MAX_BATCH_SIZE = 50; // Limits gas consumption in batch operations
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // --- Structs ---
    /// @notice Stores contributor details.
    struct Contributor {
        uint128 contribution; // ETH contributed in wei
        uint128 vestedTokens; // Vested tokens (after TGE unlock)
        uint128 releasedTokens; // Released vested tokens
        uint48 vestingStart; // Vesting start time
    }

    /// @notice Stores timelock action details.
    struct TimelockAction {
        uint48 scheduledTime; // Execution time
        bool executed; // Execution status
        ActionType actionType; // Action type
        bytes data; // Additional data (e.g., token address for recovery)
    }

    /// @notice Sale state details.
    struct SaleState {
        bool initialized; // Sale initialization status
        bool active; // Sale active status
    }

    /// @notice Vesting status returned by view function.
    struct VestingStatus {
        uint256 totalAmount;
        uint256 released;
        uint256 releasable;
        uint256 initialUnlock;
        uint48 startTime;
        uint48 duration;
    }

    // --- Enums ---
    /// @notice Types of timelock actions.
    enum ActionType {
        WithdrawFunds,
        RecoverUnsoldTokens,
        RecoverNonRyzkTokens
    }

    // --- State Variables ---
    IERC20 public immutable token; // Sale token (RYZX)
    address public treasuryWallet; // Treasury wallet
    uint48 public immutable deploymentTimestamp; // Deployment time
    uint48 public saleStartTime; // Sale start time
    uint48 public saleEndTime; // Sale end time
    uint48 public timelockDelay = 3 days; // Timelock delay with non-zero default
    uint128 private _totalRaised; // Total ETH raised
    uint128 private _totalTokensSold; // Total tokens sold
    uint32 private _contributorCount; // Number of contributors
    SaleState public saleState = SaleState({initialized: false, active: false}); // Sale state
    bool public emergencyStopped; // Emergency stop state
    bytes32 public merkleRoot; // Merkle root for whitelisting
    uint32 private _merkleNonce = 1; // Nonce for Merkle whitelisting
    uint32 private _timelockNonce = 1; // Timelock nonce with non-zero default
    uint32 public pendingTimelockActions; // Number of pending timelock actions

    // --- Mappings ---
    mapping(address => Contributor) private _contributors; // Contributor data
    mapping(bytes32 => TimelockAction) public timelockActions; // Timelock actions
    mapping(address => uint32) private _usedNonces; // Nonces used in whitelisting

    // --- Events ---
    event TimelockDelayUpdated(uint48 indexed oldDelay, uint48 indexed newDelay);
    event TokensPurchased(address indexed buyer, uint256 ethAmount, uint256 tgeTokens, uint256 vestedTokens);
    event VestingReleased(address indexed contributor, uint256 amount, bool completed);
    event BatchVestingReleased(uint256 totalReleased, uint256 contributorsProcessed);
    event MerkleRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event ContributorAdded(address indexed contributor, uint32 newCount);
    event SaleInitialized(uint48 indexed startTime, uint48 indexed endTime);
    event SaleEnded(uint128 indexed totalRaised, uint128 indexed totalSold);
    event ActionScheduled(bytes32 indexed actionId, ActionType indexed actionType, uint48 scheduledTime, bytes data);
    event ActionExecuted(bytes32 indexed actionId, ActionType indexed actionType);
    event ActionCanceled(bytes32 indexed actionId, ActionType indexed actionType);
    event FundsWithdrawn(address indexed recipient, uint256 amount);
    event UnsoldTokensRecovered(address indexed recipient, uint256 amount);
    event NonRyzkTokensRecovered(address indexed token, address indexed recipient, uint256 amount);
    event SalePaused(bool indexed paused);
    event EmergencyStop(bool indexed stopped);
    event TreasuryWalletUpdated(address indexed oldWallet, address indexed newWallet);
    event SalePeriodExtended(uint48 indexed newEndTime);
    event RoleChanged(bytes32 indexed role, address indexed account, bool granted);
    event TokenWithdrawn(address indexed token, address indexed recipient, uint256 amount);

    // --- Errors ---
    error InvalidParameter(string parameter);
    error SaleNotActive();
    error InsufficientTokens();
    error CapExceeded();
    error InvalidProof();
    error NoTokensToRelease();
    error VestingNotActive();
    error TimelockPending();
    error TimelockNotReady();
    error EmergencyStopped();
    error UnauthorizedDeposit();
    error BatchSizeExceeded();
    error CannotWithdrawNativeToken();
    error InvalidTokenAddress();

    // --- Modifiers ---
    modifier whenNotStopped() {
        if (emergencyStopped) revert EmergencyStopped();
        _;
    }

    modifier onlyValidSale() {
        if (!saleState.initialized || !saleState.active) revert SaleNotActive();
        _;
    }

    // --- Constructor ---
    constructor(address _token, address _treasuryWallet, address _admin) payable {
        if (_token == address(0)) revert InvalidParameter("token");
        if (_treasuryWallet == address(0)) revert InvalidParameter("treasuryWallet");
        if (_admin == address(0)) revert InvalidParameter("admin");
        if (_treasuryWallet == _token) revert InvalidParameter("treasuryWallet");
        
        token = IERC20(_token);
        treasuryWallet = _treasuryWallet;
        deploymentTimestamp = uint48(block.timestamp);
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        emit RoleChanged(DEFAULT_ADMIN_ROLE, _admin, true);
        emit RoleChanged(ADMIN_ROLE, _admin, true);
    }

    // --- Admin Functions ---
    /// @notice Initializes the sale.
    /// @param startTime Sale start time.
    /// @param endTime Sale end time.
    /// @param _merkleRoot Merkle root for whitelisting.
    function initializeSale(
        uint48 startTime,
        uint48 endTime,
        bytes32 _merkleRoot
    ) external onlyRole(ADMIN_ROLE) whenNotStopped {
        if (_merkleRoot == bytes32(0)) revert InvalidParameter("merkleRoot");
        if (saleState.initialized) revert InvalidParameter("alreadyInitialized");
        
        uint48 currentTime = uint48(block.timestamp);
        if (startTime <= currentTime || endTime <= startTime) {
            revert InvalidParameter("timeRange");
        }
        
        address self = address(this);
        if (token.balanceOf(self) < PUBLIC_ALLOCATION) {
            revert InvalidParameter("tokenBalance");
        }
        
        saleStartTime = startTime;
        saleEndTime = endTime;
        merkleRoot = _merkleRoot;
        SaleState storage state = saleState;
        state.initialized = true;
        state.active = true;
        
        emit SaleInitialized(startTime, endTime);
        emit MerkleRootUpdated(bytes32(0), _merkleRoot);
    }

    /// @notice Updates the timelock delay.
    /// @param newDelay New delay in seconds (1 hour to 30 days).
    function updateTimelockDelay(uint48 newDelay) 
        external 
        onlyRole(ADMIN_ROLE) 
        whenNotStopped
    {
        if (newDelay < ONE_HOUR || newDelay > THIRTY_DAYS) {
            revert InvalidParameter("timelockDelay");
        }
        uint48 oldDelay = timelockDelay;
        if (oldDelay == newDelay) return;
        timelockDelay = newDelay;
        emit TimelockDelayUpdated(oldDelay, newDelay);
    }

    /// @notice Schedules a timelock action.
    /// @param actionType Type of action.
    /// @param data Additional data (e.g., token address for recovery).
    function scheduleTimelockAction(
        ActionType actionType, 
        bytes memory data
    ) external onlyRole(ADMIN_ROLE) whenNotStopped {
        SaleState storage state = saleState;
        if (state.active) revert InvalidParameter("saleActive");
        
        if (actionType == ActionType.RecoverNonRyzkTokens) {
            if (data.length != 32) revert InvalidParameter("invalidData");
            address recoverToken = abi.decode(data, (address));
            if (recoverToken == address(0) || recoverToken == address(token)) {
                revert InvalidParameter("invalidToken");
            }
        }
        
        bytes32 actionId = keccak256(
            abi.encodePacked(
                actionType, 
                _timelockNonce, 
                data, 
                block.timestamp
            )
        );
        
        if (timelockActions[actionId].scheduledTime != 0) {
            revert TimelockPending();
        }
        
        uint48 scheduledTime = uint48(block.timestamp) + timelockDelay;
        timelockActions[actionId] = TimelockAction(scheduledTime, false, actionType, data);
        pendingTimelockActions += 1;
        _timelockNonce += 1;
        emit ActionScheduled(actionId, actionType, scheduledTime, data);
    }

    /// @notice Executes a timelock action.
    /// @param actionId Action ID.
    /// @param actionType Action type.
    /// @param data Action data (must match scheduled data).
    function executeTimelockAction(
        bytes32 actionId, 
        ActionType actionType, 
        bytes memory data
    ) external nonReentrant onlyRole(ADMIN_ROLE) whenNotStopped {
        TimelockAction storage action = timelockActions[actionId];
        if (action.scheduledTime == 0 || action.executed || action.actionType != actionType) {
            revert InvalidParameter("actionId");
        }
        if (keccak256(action.data) != keccak256(data)) revert InvalidParameter("dataMismatch");
        if (block.timestamp < action.scheduledTime) revert TimelockNotReady();
        
        action.executed = true;
        pendingTimelockActions -= 1;
        address treasury = treasuryWallet;
        address self = address(this);
        
        if (actionType == ActionType.WithdrawFunds) {
            uint256 balance = address(this).balance;
            if (balance != 0) {
                (bool sent,) = treasury.call{value: balance}("");
                if (!sent) revert InvalidParameter("withdrawal");
                emit FundsWithdrawn(treasury, balance);
            }
        } else if (actionType == ActionType.RecoverUnsoldTokens) {
            uint256 unsold = token.balanceOf(self);
            if (unsold != 0) {
                token.safeTransfer(treasury, unsold);
                emit UnsoldTokensRecovered(treasury, unsold);
            }
        } else if (actionType == ActionType.RecoverNonRyzkTokens) {
            address recoverToken = abi.decode(data, (address));
            IERC20 erc20Token = IERC20(recoverToken);
            uint256 balance = erc20Token.balanceOf(self);
            if (balance != 0) {
                erc20Token.safeTransfer(treasury, balance);
                emit NonRyzkTokensRecovered(recoverToken, treasury, balance);
            }
        }
        
        emit ActionExecuted(actionId, actionType);
    }

    /// @notice Cancels a timelock action.
    /// @param actionId Action ID.
    /// @param actionType Action type.
    /// @param data Action data (must match scheduled data).
    function cancelTimelockAction(
        bytes32 actionId, 
        ActionType actionType, 
        bytes memory data
    ) external onlyRole(ADMIN_ROLE) whenNotStopped {
        TimelockAction storage action = timelockActions[actionId];
        if (
            action.scheduledTime == 0 || 
            action.executed || 
            action.actionType != actionType ||
            keccak256(action.data) != keccak256(data)
        ) {
            revert InvalidParameter("actionId");
        }
        
        delete timelockActions[actionId];
        pendingTimelockActions -= 1;
        emit ActionCanceled(actionId, actionType);
    }

    /// @notice Pauses or unpauses the sale.
    function setSalePaused(bool paused) external onlyRole(ADMIN_ROLE) whenNotStopped {
        SaleState storage state = saleState;
        if (!state.initialized) revert InvalidParameter("notInitialized");
        if (state.active == !paused) return;
        state.active = !paused;
        emit SalePaused(paused);
    }

    /// @notice Sets emergency stop state.
    function setEmergencyStop(bool stopped) external onlyRole(ADMIN_ROLE) {
        if (emergencyStopped == stopped) return;
        emergencyStopped = stopped;
        SaleState storage state = saleState;
        if (stopped && state.active) {
            state.active = false;
        }
        emit EmergencyStop(stopped);
    }

    /// @notice Updates the treasury wallet.
    function updateTreasuryWallet(address newWallet) external onlyRole(ADMIN_ROLE) whenNotStopped {
        if (newWallet == address(0)) revert InvalidParameter("newWallet");
        if (newWallet == address(token)) revert InvalidParameter("newWallet");
        address oldWallet = treasuryWallet;
        if (oldWallet == newWallet) return;
        treasuryWallet = newWallet;
        emit TreasuryWalletUpdated(oldWallet, newWallet);
    }

    /// @notice Extends the sale period.
    function extendSalePeriod(uint48 newEndTime) external onlyRole(ADMIN_ROLE) whenNotStopped {
        SaleState storage state = saleState;
        if (!state.initialized) revert InvalidParameter("notInitialized");
        if (!state.active) revert InvalidParameter("saleNotActive");
        if (newEndTime <= saleEndTime) revert InvalidParameter("newEndTime");
        saleEndTime = newEndTime;
        emit SalePeriodExtended(newEndTime);
    }

    /// @notice Grants a role to an account.
    function grantRoleToAddress(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotStopped {
        if (account == address(0)) revert InvalidParameter("account");
        if (hasRole(role, account)) return;
        _grantRole(role, account);
        emit RoleChanged(role, account, true);
    }

    /// @notice Revokes a role from an account.
    function revokeRoleFromAddress(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotStopped {
        if (account == address(0)) revert InvalidParameter("account");
        if (!hasRole(role, account)) revert InvalidParameter("role");
        _revokeRole(role, account);
        emit RoleChanged(role, account, false);
    }

    // --- Public Functions ---
    /// @notice Purchases tokens.
    function buyTokens(bytes32[] calldata proof) external payable nonReentrant whenNotStopped {
        address caller = msg.sender;
        if (caller == address(0)) revert InvalidParameter("caller");
        if (msg.value == 0) revert InvalidParameter("zeroContribution");
        if (!isWhitelisted(caller, proof)) revert InvalidProof();
        _buyTokens(caller, msg.value);
    }

    /// @notice Releases vested tokens for a contributor.
    function releaseVestedTokens(address contributor) external nonReentrant whenNotStopped {
        if (msg.sender != contributor && !hasRole(ADMIN_ROLE, msg.sender)) {
            revert InvalidParameter("caller");
        }
        
        Contributor storage contrib = _contributors[contributor];
        uint128 vestedTokens = contrib.vestedTokens;
        if (vestedTokens == 0) revert VestingNotActive();
        
        uint256 vested = _calculateVested(contrib);
        uint256 releasable = vested - contrib.releasedTokens;
        if (releasable == 0) revert NoTokensToRelease();
        
        contrib.releasedTokens = uint128(vested);
        token.safeTransfer(contributor, releasable);
        bool completed = vested >= vestedTokens;
        emit VestingReleased(contributor, releasable, completed);
    }

    /// @notice Releases vested tokens for multiple contributors.
    function batchReleaseVestedTokens(address[] calldata contributors) 
        external 
        nonReentrant 
        onlyRole(ADMIN_ROLE) 
        whenNotStopped 
    {
        uint256 length = contributors.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        uint256 totalReleasable;
        uint256 processed;
        
        for (uint256 i = 0; i < length;) {
            address contributor = contributors[i];
            Contributor storage contrib = _contributors[contributor];
            
            if (contrib.vestedTokens == 0) {
                unchecked { ++i; }
                continue;
            }
            
            uint256 vested = _calculateVested(contrib);
            uint256 releasable = vested - contrib.releasedTokens;
            if (releasable == 0) {
                unchecked { ++i; }
                continue;
            }
            
            contrib.releasedTokens = uint128(vested);
            token.safeTransfer(contributor, releasable);
            totalReleasable += releasable;
            processed++;
            unchecked { ++i; }
        }
        
        if (totalReleasable != 0) {
            emit BatchVestingReleased(totalReleasable, processed);
        }
    }

    // --- View Functions ---
    /// @notice Gets the contract's ETH balance.
    function selfBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Checks if a user is whitelisted.
    function isWhitelisted(address user, bytes32[] memory proof) public view returns (bool) {
        if (user == address(0)) revert InvalidParameter("user");
        bytes32 leaf = keccak256(abi.encodePacked(user, _usedNonces[user]));
        return proof.verify(merkleRoot, leaf);
    }

    /// @notice Gets a contributor's details.
    function getContribution(address contributor)
        external
        view
        returns (
            uint128 contribution,
            uint128 vestedTokens,
            uint128 releasedTokens,
            uint128 releasableTokens,
            uint48 vestingStart
        )
    {
        Contributor storage contrib = _contributors[contributor];
        contribution = contrib.contribution;
        vestedTokens = contrib.vestedTokens;
        releasedTokens = contrib.releasedTokens;
        vestingStart = contrib.vestingStart;
        
        if (contrib.vestedTokens == 0) {
            releasableTokens = 0;
        } else {
            uint256 vested = _calculateVested(contrib);
            releasableTokens = uint128(vested - contrib.releasedTokens);
        }
    }

    /// @notice Gets vesting status for a contributor.
    function getVestingStatus(address contributor) 
        external 
        view 
        returns (VestingStatus memory status) 
    {
        Contributor storage contrib = _contributors[contributor];
        status.totalAmount = contrib.vestedTokens;
        status.released = contrib.releasedTokens;
        status.initialUnlock = (contrib.vestedTokens * TGE_UNLOCK_PERCENT) / 100;
        status.startTime = contrib.vestingStart;
        status.duration = 12 * 30 days; // 12-month vesting
        
        if (status.totalAmount == 0) {
            status.releasable = 0;
        } else {
            uint256 vested = _calculateVested(contrib);
            status.releasable = vested - status.released;
        }
    }

    /// @notice Gets timelock action details.
    function getTimelockAction(bytes32 actionId)
        external
        view
        returns (uint48 scheduledTime, bool executed, ActionType actionType, bytes memory data)
    {
        TimelockAction storage action = timelockActions[actionId];
        scheduledTime = action.scheduledTime;
        executed = action.executed;
        actionType = action.actionType;
        data = action.data;
    }

    /// @notice Gets timelock status.
    function getTimelockStatus() external view returns (uint32 pendingCount, uint48 delay) {
        pendingCount = pendingTimelockActions;
        delay = timelockDelay;
    }

    // --- Internal Functions ---
    /// @notice Handles token purchase logic.
    function _buyTokens(address buyer, uint256 ethValue) private {
        SaleState storage state = saleState;
        uint48 currentTime = uint48(block.timestamp);
        uint128 currentTotalRaised = _totalRaised;
        uint128 currentTotalTokensSold = _totalTokensSold;
        
        if (!state.active || currentTime < saleStartTime || currentTime >= saleEndTime) {
            revert SaleNotActive();
        }
        if (ethValue < MIN_CONTRIBUTION || ethValue > MAX_CONTRIBUTION) {
            revert InvalidParameter("ethValue");
        }
        
        Contributor storage contrib = _contributors[buyer];
        uint128 currentContribution = contrib.contribution;
        uint128 newUserContribution = currentContribution + uint128(ethValue);
        
        if (newUserContribution > MAX_USER_CONTRIBUTION) revert CapExceeded();
        
        uint256 totalTokens = (ethValue * 1e18) / TOKEN_PRICE;
        uint128 newTotalTokensSold = currentTotalTokensSold + uint128(totalTokens);
        
        if (newTotalTokensSold > PUBLIC_ALLOCATION) revert InsufficientTokens();
        if (currentTotalRaised + uint128(ethValue) > SALE_CAP) revert CapExceeded();
        
        uint256 tgeTokens = (totalTokens * TGE_UNLOCK_PERCENT) / 100;
        uint256 vestedTokens = totalTokens - tgeTokens;
        
        _totalRaised = currentTotalRaised + uint128(ethValue);
        _totalTokensSold = newTotalTokensSold;
        
        bool isNewContributor = currentContribution == 0;
        if (isNewContributor) {
            contrib.vestingStart = currentTime;
            _contributorCount += 1;
            emit ContributorAdded(buyer, _contributorCount);
        }
        
        contrib.contribution = newUserContribution;
        contrib.vestedTokens += uint128(vestedTokens);
        contrib.releasedTokens += uint128(tgeTokens);
        
        _usedNonces[buyer] = _merkleNonce;
        _merkleNonce += 1;
        
        token.safeTransfer(buyer, tgeTokens);
        emit TokensPurchased(buyer, ethValue, tgeTokens, vestedTokens);
        
        if (currentTotalRaised + uint128(ethValue) >= SALE_CAP || newTotalTokensSold >= PUBLIC_ALLOCATION) {
            state.active = false;
            emit SaleEnded(currentTotalRaised + uint128(ethValue), newTotalTokensSold);
        }
    }

    /// @notice Calculates vested tokens based on elapsed time.
    function _calculateVested(Contributor storage contrib) private view returns (uint256 vested) {
        uint128 vestedTokens = contrib.vestedTokens;
        uint48 vestingStart = contrib.vestingStart;
        uint48 duration = 12 * 30 days; // 12-month vesting
        
        if (block.timestamp >= vestingStart + duration) {
            return vestedTokens;
        }
        if (block.timestamp <= vestingStart) {
            return contrib.releasedTokens;
        }
        
        uint48 elapsed = uint48(block.timestamp) - vestingStart;
        return (vestedTokens * elapsed) / duration;
    }

    /// @notice Restricts direct ETH deposits.
    receive() external payable {
        revert UnauthorizedDeposit();
    }

    // --- Withdraw Function for Unexpected Tokens ---
    function withdrawToken(
        address tokenAddress,
        uint256 amount,
        address recipient
    ) external onlyRole(ADMIN_ROLE) whenNotStopped {
        if (tokenAddress == address(0)) revert InvalidTokenAddress();
        if (recipient == address(0)) revert InvalidParameter("recipient");
        if (tokenAddress == address(token)) revert CannotWithdrawNativeToken();
        
        IERC20(tokenAddress).safeTransfer(recipient, amount);
        emit TokenWithdrawn(tokenAddress, recipient, amount);
    }

    // --- Interface Support ---
    function supportsInterface(bytes4 interfaceId) 
        public 
        view 
        override(AccessControl, IERC721Receiver) 
        returns (bool) 
    {
        return interfaceId == type(IERC20).interfaceId ||
               interfaceId == type(AccessControl).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}