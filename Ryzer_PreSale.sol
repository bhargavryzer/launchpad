// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title RyzerPresale
 * @notice Presale contract for Ryzer token with vesting and timelock functionality
 */
contract RyzerPresale is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    // Constants
    uint256 private constant MIN_CONTRIBUTION = 100 ether; // 100 ETH minimum contribution
    uint256 private constant MAX_CONTRIBUTION = 30_000 ether; // 30,000 ETH maximum per transaction
    uint256 private constant MAX_USER_CONTRIBUTION = 100_000 ether; // 100,000 ETH maximum per user
    uint256 private constant SALE_CAP = 1_500_000 ether; // 1,500,000 ETH total cap
    uint48 private constant ONE_MONTH = 90 days;
    uint256 private constant TGE_UNLOCK_PERCENT = 50; // 50% TGE unlock for Presale
    uint256 private constant PRECISION = 1e18; // Precision for vesting calculations
    uint256 private constant TOKEN_PRICE = 0.05 ether; // 0.05 ETH per token (20 tokens per ETH)
    uint256 private constant PRESALE_ALLOCATION = 30_000_000e18; // 30 million tokens for presale
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    // Events
    event TimelockDelayUpdated(uint48 indexed oldDelay, uint48 indexed newDelay);
    event PresaleTokensPurchased(address indexed buyer, uint256 ethAmount, uint256 tokenAmount, uint256 tgeTokens, uint256 vestedTokens);
    event VestingReleased(address indexed contributor, uint256 amount, bool completed);
    event BatchVestingReleased(uint256 totalReleased, uint256 contributorsProcessed);
    event MerkleRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event ContributorAdded(address indexed contributor, uint32 newCount);
    event SaleInitialized(uint48 indexed presaleStart, uint48 presaleEnd);
    event SalePhaseEnded(uint128 indexed totalRaised, uint128 totalSold);
    event ActionScheduled(bytes32 indexed actionId, ActionType indexed actionType, uint48 scheduledTime, bytes data);
    event ActionExecuted(bytes32 indexed actionId, ActionType indexed actionType);
    event ActionCanceled(bytes32 indexed actionId, ActionType indexed actionType);
    event FundsWithdrawn(address indexed recipient, uint256 amount);
    event UnsoldTokensRecovered(address indexed recipient, uint256 amount);
    event NonRyzkTokensRecovered(address indexed token, address indexed recipient, uint256 amount);
    event SalePaused(bool paused);
    event EmergencyStop(bool indexed stopped);
    event TreasuryWalletUpdated(address indexed oldWallet, address indexed newWallet);
    event SalePeriodExtended(uint48 indexed newEndTime);
    event CircuitBreakerTriggered(address indexed triggeredBy, string reason);

    // Errors
    error InvalidParameter(string parameter);
    error SaleNotActive();
    error InsufficientTokens();
    error CapExceeded();
    error InvalidProof();
    error NoTokensToRelease();
    error CliffNotPassed();
    error TimelockPending();
    error TimelockNotReady();
    error EmergencyStopped();
    error UnauthorizedDeposit();
    error BatchSizeExceeded();
    error CannotWithdrawNativeToken();
    error InvalidTokenAddress();
    error CircuitBreakerEngaged();

    // Enums
    enum ActionType {
        WithdrawPresaleFunds,
        RecoverUnsoldTokens,
        RecoverNonRyzkTokens
    }
    
    enum WalletType {
        Treasury,
        Team,
        Private,
        Staking,
        Marketing,
        DexLiquidity,
        CexLiquidity
    }

    // Structs
    struct Contributor {
        uint128 presaleContribution; // ETH contributed in wei
        uint128 presaleVestedTokens; // Vested tokens (after TGE unlock)
        uint128 presaleReleased; // Released vested tokens
        uint48 presaleVestingStart; // Vesting start time
    }
    
    struct TimelockAction {
        uint48 scheduledTime; // Execution time
        bool executed; // Execution status
        ActionType actionType; // Action type
        bytes data; // Additional data (e.g., token address for recovery)
    }
    
    struct VestingStatus {
        uint256 totalAmount;
        uint256 released;
        uint256 releasable;
        uint256 initialUnlock;
        uint256 startTime;
        uint256 duration;
        uint256 cliff;
    }
    
    struct SaleState {
        bool initialized; // Sale initialization status
        bool active; // Sale active status
        bool circuitBreaker; // Circuit breaker status
    }
    
    // State variables
    IERC20 public immutable token;
    address public treasuryWallet;
    uint48 public presaleStartTime;
    uint48 public presaleEndTime;
    bytes32 public presaleMerkleRoot;
    uint48 public timelockDelay = 3 days; // Default 3-day delay
    uint48 private _timelockNonce;
    uint128 private _presaleTotalRaised;
    uint128 private _presaleTokensSold;
    uint32 private _presaleContributorCount;
    mapping(address => Contributor) private _contributors;
    mapping(bytes32 => TimelockAction) public timelockActions;
    mapping(address => uint32) private _presaleUsedNonces;
    uint32 public pendingTimelockActions;
    bool public emergencyStopped;
    SaleState public saleState;
    
    /**
     * @notice Initializes the contract with required roles and parameters
     * @param _token Address of the token being sold
     * @param _treasuryWallet Address to receive funds
     * @param _admin Initial admin address
     */
    constructor(
        address _token,
        address _treasuryWallet,
        address _admin
    ) {
        if (_token == address(0) || _treasuryWallet == address(0) || _admin == address(0)) {
            revert InvalidParameter("zeroAddress");
        }
        
        token = IERC20(_token);
        treasuryWallet = _treasuryWallet;
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
    }

    /**
     * @notice Initialize the presale with specific dates and merkle root
     * @param startTime Start time of the presale
     * @param endTime End time of the presale
     * @param merkleRoot Root of the merkle tree containing whitelisted addresses
     */
    function initializeSale(
        uint48 startTime,
        uint48 endTime,
        bytes32 merkleRoot
    ) external onlyRole(ADMIN_ROLE) {
        if (saleState.initialized) {
            revert InvalidParameter("alreadyInitialized");
        }
        
        if (startTime < block.timestamp + 1 days || endTime <= startTime) {
            revert InvalidParameter("invalidTimeRange");
        }
        
        if (token.balanceOf(address(this)) < PRESALE_ALLOCATION) {
            revert InsufficientTokens();
        }
        
        presaleStartTime = startTime;
        presaleEndTime = endTime;
        presaleMerkleRoot = merkleRoot;
        
        SaleState storage state = saleState;
        state.initialized = true;
        state.active = true;
        
        emit SaleInitialized(startTime, endTime);
        emit MerkleRootUpdated(bytes32(0), merkleRoot);
    }

    /**
     * @notice Buy presale tokens with ETH
     * @param proof Merkle proof to verify address eligibility
     */
    function buyPresaleTokens(bytes32[] calldata proof) external payable nonReentrant whenNotStopped {
        if (!saleState.active || block.timestamp < presaleStartTime || block.timestamp >= presaleEndTime) {
            revert SaleNotActive();
        }
        
        if (msg.value < MIN_CONTRIBUTION || msg.value > MAX_CONTRIBUTION) {
            revert InvalidParameter("invalidContribution");
        }
        
        Contributor storage contrib = _contributors[msg.sender];
        uint128 currentContribution = contrib.presaleContribution;
        uint128 newUserContribution = currentContribution + uint128(msg.value);
        
        if (newUserContribution > MAX_USER_CONTRIBUTION) {
            revert CapExceeded();
        }
        
        // Verify merkle proof
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, uint32(0)));
        if (!_verifyMerkle(leaf, proof)) {
            revert InvalidProof();
        }
        
        // Calculate tokens and check allocation
        uint256 totalTokens = (msg.value * 1e18) / TOKEN_PRICE;
        uint256 currentTokensSold = _presaleTokensSold;
        
        if (currentTokensSold + totalTokens > PRESALE_ALLOCATION) {
            revert InsufficientTokens();
        }
        
        // Update state
        uint48 currentTime = uint48(block.timestamp);
        uint256 tgeTokens = (totalTokens * TGE_UNLOCK_PERCENT) / 100;
        uint256 vestedTokens = totalTokens - tgeTokens;
        
        _presaleTotalRaised += uint128(msg.value);
        _presaleTokensSold += uint128(totalTokens);
        
        bool isNewContributor = currentContribution == 0;
        if (isNewContributor) {
            contrib.presaleVestingStart = currentTime;
            _presaleContributorCount++;
            emit ContributorAdded(msg.sender, _presaleContributorCount);
        }
        
        // Update contributor info
        contrib.presaleContribution = newUserContribution;
        contrib.presaleVestedTokens += uint128(vestedTokens);
        
        // Transfer TGE tokens
        if (tgeTokens > 0) {
            token.safeTransfer(msg.sender, tgeTokens);
        }
        
        emit PresaleTokensPurchased(msg.sender, msg.value, totalTokens, tgeTokens, vestedTokens);
    }

    /**
     * @notice Release vested tokens to contributor
     * @param account Contributor address
     */
    function releaseVestedTokens(address account) external nonReentrant {
        if (account != msg.sender && !hasRole(ADMIN_ROLE, msg.sender)) {
            revert InvalidParameter("unauthorized");
        }
        
        Contributor storage contrib = _contributors[account];
        if (contrib.presaleVestingStart == 0) {
            revert InvalidParameter("noContribution");
        }
        
        uint256 vestingStart = contrib.presaleVestingStart;
        if (block.timestamp < vestingStart + 4 * ONE_MONTH) {
            revert CliffNotPassed();
        }
        
        uint256 totalVested = _calculateVested(contrib);
        uint256 alreadyReleased = contrib.presaleReleased;
        
        if (totalVested == 0 || totalVested == alreadyReleased) {
            revert NoTokensToRelease();
        }
        
        uint256 amountToRelease = totalVested - alreadyReleased;
        contrib.presaleReleased = uint128(alreadyReleased + amountToRelease);
        
        token.safeTransfer(account, amountToRelease);
        
        bool completed = contrib.presaleReleased == (contrib.presaleVestedTokens + ((contrib.presaleVestedTokens * TGE_UNLOCK_PERCENT) / 100));
        
        emit VestingReleased(account, amountToRelease, completed);
    }

    /**
     * @notice Batch release of vested tokens to multiple contributors
     * @param accounts Contributor addresses
     */
    function batchReleaseVestedTokens(address[] memory accounts) external nonReentrant onlyRole(ADMIN_ROLE) {
        if (accounts.length > 50) {
            revert BatchSizeExceeded();
        }
        
        uint256 totalReleasable;
        uint256 totalAccountsProcessed;
        
        for (uint256 i = 0; i < accounts.length; i++) {
            address account = accounts[i];
            Contributor storage contrib = _contributors[account];
            
            if (contrib.presaleVestingStart == 0) {
                continue;
            }
            
            if (block.timestamp < contrib.presaleVestingStart + 4 * ONE_MONTH) {
                continue;
            }
            
            uint256 totalVested = _calculateVested(contrib);
            uint256 alreadyReleased = contrib.presaleReleased;
            
            if (totalVested == 0 || totalVested == alreadyReleased) {
                continue;
            }
            
            uint256 amountToRelease = totalVested - alreadyReleased;
            contrib.presaleReleased = uint128(alreadyReleased + amountToRelease);
            
            totalReleasable += amountToRelease;
            totalAccountsProcessed++;
            
            token.safeTransfer(account, amountToRelease);
        }
        
        if (totalReleasable > 0) {
            emit BatchVestingReleased(totalReleasable, totalAccountsProcessed);
        }
    }

    /**
     * @notice Schedule a timelock action
     * @param actionType Type of action to schedule
     * @param data Extra data for action execution
     */
    function scheduleTimelockAction(ActionType actionType, bytes memory data) external onlyRole(ADMIN_ROLE) {
        if (saleState.active) {
            revert InvalidParameter("saleActive");
        }
        
        if (actionType == ActionType.RecoverNonRyzkTokens) {
            if (data.length != 32) {
                revert InvalidParameter("invalidData");
            }
            
            address recoverToken = abi.decode(data, (address));
            if (recoverToken == address(0) || recoverToken == address(token)) {
                revert InvalidTokenAddress();
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
        timelockActions[actionId] = TimelockAction({
            scheduledTime: scheduledTime,
            executed: false,
            actionType: actionType,
            data: data
        });
        
        pendingTimelockActions++;
        _timelockNonce++;
        
        emit ActionScheduled(actionId, actionType, scheduledTime, data);
    }

    /**
     * @notice Execute a previously scheduled timelock action
     * @param actionId Action ID to execute
     * @param actionType Type of action to execute
     * @param data Extra data for action execution
     */
    function executeTimelockAction(
        bytes32 actionId,
        ActionType actionType,
        bytes memory data
    ) external onlyRole(ADMIN_ROLE) nonReentrant {
        TimelockAction storage action = timelockActions[actionId];
        
        if (
            action.scheduledTime == 0 ||
            action.executed ||
            action.actionType != actionType ||
            keccak256(action.data) != keccak256(data)
        ) {
            revert InvalidParameter("invalidAction");
        }
        
        if (block.timestamp < action.scheduledTime) {
            revert TimelockNotReady();
        }
        
        action.executed = true;
        pendingTimelockActions--;
        
        address treasury = treasuryWallet;
        address self = address(this);
        
        if (actionType == ActionType.WithdrawPresaleFunds) {
            uint256 balance = _presaleTotalRaised;
            if (balance == 0) {
                revert InvalidParameter("noFunds");
            }
            
            delete _presaleTotalRaised;
            (bool sent, ) = treasury.call{value: balance}("");
            if (!sent) {
                revert InvalidParameter("ethTransferFailed");
            }
        } else if (actionType == ActionType.RecoverUnsoldTokens) {
            uint256 unsold = token.balanceOf(self);
            if (unsold == 0) {
                revert InvalidParameter("noTokens");
            }
            
            uint256 balanceBefore = token.balanceOf(treasury);
            token.safeTransfer(treasury, unsold);
            uint256 balanceAfter = token.balanceOf(treasury);
            emit UnsoldTokensRecovered(treasury, balanceAfter - balanceBefore);
        } else if (actionType == ActionType.RecoverNonRyzkTokens) {
            (address recoverToken, ) = abi.decode(data, (address, bytes));
            if (recoverToken == address(0) || recoverToken == address(token)) {
                revert InvalidTokenAddress();
            }
            
            uint256 tokenBalance = IERC20(recoverToken).balanceOf(self);
            if (tokenBalance == 0) {
                revert InvalidParameter("noTokens");
            }
            
            IERC20(recoverToken).safeTransfer(treasuryWallet, tokenBalance);
            emit NonRyzkTokensRecovered(recoverToken, treasuryWallet, tokenBalance);
        }
        
        emit ActionExecuted(actionId, actionType);
    }

    /**
     * @notice Cancel a scheduled timelock action
     * @param actionId Action ID to cancel
     * @param actionType Type of action to cancel
     * @param data Extra data for validation
     */
    function cancelTimelockAction(
        bytes32 actionId,
        ActionType actionType,
        bytes memory data
    ) external onlyRole(ADMIN_ROLE) {
        TimelockAction storage action = timelockActions[actionId];
        
        if (
            action.scheduledTime == 0 ||
            action.executed ||
            action.actionType != actionType ||
            keccak256(action.data) != keccak256(data)
        ) {
            revert InvalidParameter("invalidAction");
        }
        
        action.scheduledTime = 0;
        action.executed = true;
        pendingTimelockActions--;
        
        emit ActionCanceled(actionId, actionType);
    }

    /**
     * @notice Pause or unpause the sale
     * @param paused New pause state
     */
    function setSalePaused(bool paused) external onlyRole(ADMIN_ROLE) {
        if (!saleState.initialized) {
            revert InvalidParameter("notInitialized");
        }
        
        if (paused == !saleState.active) {
            revert InvalidParameter("sameState");
        }
        
        saleState.active = !paused;
        emit SalePaused(paused);
    }

    /**
     * @notice Stop the sale permanently
     * @param stopped New stop state
     */
    function setEmergencyStop(bool stopped) external onlyRole(ADMIN_ROLE) {
        if (stopped == emergencyStopped) {
            revert InvalidParameter("sameState");
        }
        
        saleState.active = !stopped;
        emergencyStopped = stopped;
        
        emit EmergencyStop(stopped);
    }

    /**
     * @notice Update the treasury wallet
     * @param newWallet New treasury wallet address
     */
    function updateTreasuryWallet(address newWallet) external onlyRole(ADMIN_ROLE) {
        if (newWallet == address(0) || newWallet == address(token)) {
            revert InvalidTokenAddress();
        }
        
        emit TreasuryWalletUpdated(treasuryWallet, newWallet);
        treasuryWallet = newWallet;
    }

    /**
     * @notice Extend the presale period
     * @param newEndTime New end time for presale
     */
    function extendSalePeriod(uint48 newEndTime) external onlyRole(ADMIN_ROLE) {
        if (!saleState.initialized) {
            revert InvalidParameter("notInitialized");
        }
        
        if (!saleState.active) {
            revert InvalidParameter("saleNotActive");
        }
        
        if (newEndTime <= presaleEndTime) {
            revert InvalidParameter("invalidEndTime");
        }
        
        presaleEndTime = newEndTime;
        emit SalePeriodExtended(newEndTime);
    }

    /**
     * @notice Grant role to an address
     * @param role Role to grant
     * @param account Address to grant role to
     */
    function grantRoleToAddress(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        if (account == address(0)) {
            revert InvalidParameter("zeroAddress");
        }
        
        _grantRole(role, account);
    }

    /**
     * @notice Revoke role from an address
     * @param role Role to revoke
     * @param account Address to revoke role from
     */
    function revokeRoleFromAddress(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        if (account == address(0)) {
            revert InvalidParameter("zeroAddress");
        }
        
        _revokeRole(role, account);
    }

    /**
     * @notice Update the timelock delay
     * @param newDelay New delay in seconds (must be between 1 hour and 30 days)
     */
    function updateTimelockDelay(uint48 newDelay) external onlyRole(ADMIN_ROLE) {
        if (newDelay < 1 hours || newDelay > 30 days) {
            revert InvalidParameter("delayOutOfRange");
        }
        
        emit TimelockDelayUpdated(timelockDelay, newDelay);
        timelockDelay = newDelay;
    }

    /**
     * @notice Trigger circuit breaker to halt operations
     * @param reason Reason for triggering circuit breaker
     */
    function triggerCircuitBreaker(string calldata reason) external onlyRole(ADMIN_ROLE) {
        if (!saleState.circuitBreaker) {
            saleState.circuitBreaker = true;
            emit CircuitBreakerTriggered(msg.sender, reason);
        }
    }

    /**
     * @notice Get contributor details
     * @param account Address to query
     * @return Contributor struct with details
     */
    function getContribution(address account) external view returns (Contributor memory) {
        return _contributors[account];
    }

    /**
     * @notice Get vesting status for a contributor
     * @param account Address to query
     * @return VestingStatus struct with details
     */
    function getVestingStatus(address account) external view returns (VestingStatus memory status) {
        Contributor memory contrib = _contributors[account];
        status.totalAmount = contrib.presaleVestedTokens + ((contrib.presaleVestedTokens * TGE_UNLOCK_PERCENT) / 100);
        status.released = contrib.presaleReleased;
        status.startTime = contrib.presaleVestingStart;
        status.duration = 12 * ONE_MONTH;
        status.cliff = 4 * ONE_MONTH;
        
        if (status.totalAmount == 0 || block.timestamp < contrib.presaleVestingStart + status.cliff) {
            status.releasable = 0;
        } else {
            uint256 vested = _calculateVested(contrib);
            status.releasable = vested - status.released;
        }
    }

    /**
     * @notice Get presale statistics
     * @return totalRaised Total ETH raised
     * @return totalSold Total tokens sold
     */
    function getSaleStats() external view returns (uint128 totalRaised, uint128 totalSold) {
        return (_presaleTotalRaised, _presaleTokensSold);
    }

    /**
     * @notice Get presale contributor count
     * @return uint32 contributor count
     */
    function getContributorCount() external view returns (uint32) {
        return _presaleContributorCount;
    }

    /**
     * @notice Get current presale state
     * @return bool indicating if emergency stop is engaged
     */
    function isEmergencyStopped() external view returns (bool) {
        return emergencyStopped;
    }

    /**
     * @notice Get presale token price
     * @return uint256 token price in wei
     */
    function getTokenPrice() external pure returns (uint256) {
        return TOKEN_PRICE;
    }

    /**
     * @notice Internal function to calculate vested tokens
     * @param contrib Contributor struct
     * @return uint256 vested tokens
     */
    function _calculateVested(Contributor memory contrib) internal pure returns (uint256) {
        if (block.timestamp < contrib.presaleVestingStart + 4 * ONE_MONTH) {
            return 0;
        }
        
        if (block.timestamp >= contrib.presaleVestingStart + 16 * ONE_MONTH) { // 4 months cliff + 12 months vesting
            return contrib.presaleVestedTokens;
        }
        
        uint48 elapsed = uint48(block.timestamp) - contrib.presaleVestingStart;
        uint48 vestingPeriod = 12 * ONE_MONTH;
        
        if (elapsed < 4 * ONE_MONTH) {
            return 0;
        }
        
        uint256 vested = (contrib.presaleVestedTokens * (elapsed - 4 * ONE_MONTH)) / vestingPeriod;
        return vested;
    }

    /**
     * @notice Verify merkle proof
     * @param leaf Leaf node to verify
     * @param proof Proof to verify
     * @return bool indicating success
     */
    function _verifyMerkle(bytes32 leaf, bytes32[] memory proof) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            computedHash = keccak256(
                computedHash < proofElement ? 
                    abi.encodePacked(computedHash, proofElement) : 
                    abi.encodePacked(proofElement, computedHash)
            );
        }
        
        return computedHash == presaleMerkleRoot;
    }

    /**
     * @notice Fallback function to prevent direct ETH deposits
     */
    receive() external payable {
        if (msg.value > 0) {
            revert UnauthorizedDeposit();
        }
    }

    /**
     * @notice Withdraw ETH that was sent directly to the contract
     */
    function withdrawDirectDeposits() external onlyRole(ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        if (balance == 0) {
            revert InvalidParameter("noFunds");
        }
        
        (bool sent, ) = treasuryWallet.call{value: balance}("");
        if (!sent) {
            revert InvalidParameter("transferFailed");
        }
        
        emit FundsWithdrawn(treasuryWallet, balance);
    }

    /**
     * @notice Get presale allocation
     * @return uint256 presale allocation
     */
    function getPresaleAllocation() external pure returns (uint256) {
        return PRESALE_ALLOCATION;
    }

    /**
     * @notice Get presale configuration
     * @return minContribution Minimum contribution
     * @return maxContribution Maximum contribution
     * @return maxUserContribution Maximum per-user contribution
     * @return saleCap Total sale cap
     */
    function getPresaleConfig() external pure returns (
        uint256 minContribution,
        uint256 maxContribution,
        uint256 maxUserContribution,
        uint256 saleCap
    ) {
        minContribution = MIN_CONTRIBUTION;
        maxContribution = MAX_CONTRIBUTION;
        maxUserContribution = MAX_USER_CONTRIBUTION;
        saleCap = SALE_CAP;
    }

    /**
     * @notice Get timelock nonce
     * @return uint256 current timelock nonce
     */
    function getTimelockNonce() external view returns (uint256) {
        return _timelockNonce;
    }

    /**
     * @notice Get presale contributor count
     * @return uint32 contributor count
     */
    function getPresaleContributorCount() external view returns (uint32) {
        return _presaleContributorCount;
    }

    /**
     * @notice Get presale used nonce for an account
     * @param account Account to query
     * @return uint32 used nonce
     */
    function getPresaleUsedNonce(address account) external view returns (uint32) {
        return _presaleUsedNonces[account];
    }

    /**
     * @notice Get presale metrics
     * @return totalRaised Total ETH raised
     * @return totalSold Total tokens sold
     * @return remainingTokens Tokens remaining in contract
     */
    function getPresaleMetrics() external view returns (
        uint256 totalRaised,
        uint256 totalSold,
        uint256 remainingTokens
    ) {
        totalRaised = _presaleTotalRaised;
        totalSold = _presaleTokensSold;
        remainingTokens = token.balanceOf(address(this));
    }

    /**
     * @notice Get timelock action count
     * @return uint32 pending actions
     */
    function getPendingTimelockActions() external view returns (uint32) {
        return pendingTimelockActions;
    }

    /**
     * @notice Get presale status
     * @return bool indicating if presale is active
     */
    function isPresaleActive() external view returns (bool) {
        return saleState.active && block.timestamp >= presaleStartTime && block.timestamp < presaleEndTime;
    }

    /**
     * @notice Get presale end time
     * @return uint48 presale end time
     */
    function getPresaleEndTime() external view returns (uint48) {
        return presaleEndTime;
    }

    /**
     * @notice Get presale start time
     * @return uint48 presale start time
     */
    function getPresaleStartTime() external view returns (uint48) {
        return presaleStartTime;
    }

    /**
     * @notice Get presale merkle root
     * @return bytes32 merkle root
     */
    function getPresaleMerkleRoot() external view returns (bytes32) {
        return presaleMerkleRoot;
    }

    /**
     * @notice Get presale token address
     * @return IERC20 token address
     */
    function getPresaleToken() external view returns (IERC20) {
        return token;
    }

    /**
     * @notice Get presale treasury wallet
     * @return address treasury wallet
     */
    function getPresaleTreasuryWallet() external view returns (address) {
        return treasuryWallet;
    }

    /**
     * @notice Get presale contributor's vesting start time
     * @param account Contributor address
     * @return uint48 vesting start time
     */
    function getPresaleVestingStart(address account) external view returns (uint48) {
        return _contributors[account].presaleVestingStart;
    }

    /**
     * @notice Get presale contributor's presale contribution
     * @param account Contributor address
     * @return uint128 presale contribution
     */
    function getPresaleContribution(address account) external view returns (uint128) {
        return _contributors[account].presaleContribution;
    }

    /**
     * @notice Get presale contributor's presale released tokens
     * @param account Contributor address
     * @return uint128 presale released tokens
     */
    function getPresaleReleasedTokens(address account) external view returns (uint128) {
        return _contributors[account].presaleReleased;
    }

    /**
     * @notice Get presale contributor's presale vested tokens
     * @param account Contributor address
     * @return uint128 presale vested tokens
     */
    function getPresaleVestedTokens(address account) external view returns (uint128) {
        return _contributors[account].presaleVestedTokens;
    }

    /**
     * @notice Check if address has a role
     * @param role Role to check
     * @param account Address to check
     * @return bool indicating if account has role
     */
    function hasRole(bytes32 role, address account) public view virtual override returns (bool) {
        return super.hasRole(role, account);
    }

    /**
     * @notice Grants a role to an account
     * @param role Role to grant
     * @param account Account to grant role to
     */
    function grantRole(bytes32 role, address account) public virtual override onlyRole(ADMIN_ROLE) {
        super.grantRole(role, account);
    }

    /**
     * @notice Revokes a role from an account
     * @param role Role to revoke
     * @param account Account to revoke role from
     */
    function revokeRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        super.revokeRole(role, account);
    }

    /**
     * @notice Returns whether the contract implements an interface for a given selector
     * @param interfaceId Selector of the interface to check
     * @return bool indicating if interface is supported
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC20).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @notice Modifier to ensure not in circuit breaker state
     */
    modifier whenNotInCircuitBreaker() {
        if (saleState.circuitBreaker) {
            revert CircuitBreakerEngaged();
        }
        _;
    }

    /**
     * @notice Modifier to ensure not in emergency stop state
     */
    modifier whenNotStopped() {
        if (emergencyStopped) {
            revert EmergencyStopped();
        }
        _;
    }
}