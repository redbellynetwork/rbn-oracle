// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {AccessControllerInterface} from "../../../shared/interfaces/AccessControllerInterface.sol";
import {IArbitrumDelayedInbox} from "../interfaces/IArbitrumDelayedInbox.sol";

import {SequencerUptimeFeed} from "../SequencerUptimeFeed.sol";
import {Validator} from "../Validator.sol";

import {AddressAliasHelper} from "../../../vendor/arb-bridge-eth/v0.8.0-custom/contracts/libraries/AddressAliasHelper.sol";
import {Address} from "../../../vendor/openzeppelin-solidity/v4.7.3/contracts/utils/Address.sol";
import {ArbSys} from "../../../vendor/@arbitrum/nitro-contracts/src/precompiles/ArbSys.sol";

/// @title ArbitrumValidator - makes xDomain L2 Flags contract call (using L2 xDomain Forwarder contract)
/// @notice Allows to raise and lower Flags on the Arbitrum L2 network through L1 bridge
///  - The internal AccessController controls the access of the validate method
///  - Gas configuration is controlled by a configurable external SimpleWriteAccessController
///  - Funds on the contract are managed by the owner
contract ArbitrumValidator is Validator {
  /// @dev Precompiled contract that exists in every Arbitrum chain at address(100). Exposes a variety of system-level functionality.
  address internal constant ARBSYS_ADDR = address(0x0000000000000000000000000000000000000064);

  // solhint-disable-next-line chainlink-solidity/all-caps-constant-storage-variables
  string public constant override typeAndVersion = "ArbitrumValidator 2.0.0";

  /// L2 xDomain alias address of this contract
  // solhint-disable-next-line chainlink-solidity/prefix-immutable-variables-with-i
  address public immutable L2_ALIAS = AddressAliasHelper.applyL1ToL2Alias(address(this));

  /// Payment strategy enumeration
  enum PaymentStrategy {
    L1,
    L2
  }

  /// Config for L1 -> L2 Arbitrum retryable ticket message
  struct GasConfig {
    uint256 maxGas;
    uint256 gasPriceBid;
    uint256 baseFee; // Will use block.baseFee if set to 0
    address gasPriceL1FeedAddr;
  }

  /// Helper Variable(s)
  AccessControllerInterface private s_configAC;
  PaymentStrategy private s_paymentStrategy;
  GasConfig private s_gasConfig;

  /// @notice emitted when a new payment strategy is set
  /// @param paymentStrategy strategy describing how the contract pays for xDomain calls
  event PaymentStrategySet(PaymentStrategy indexed paymentStrategy);

  /// @notice emitted when a new gas configuration is set
  /// @param maxGas gas limit for immediate L2 execution attempt.
  /// @param gasPriceBid maximum L2 gas price to pay
  /// @param gasPriceL1FeedAddr address of the L1 gas price feed (used to approximate Arbitrum retryable ticket submission cost)
  event GasConfigSet(uint256 maxGas, uint256 gasPriceBid, address indexed gasPriceL1FeedAddr);

  /// @notice emitted when a new gas access-control contract is set
  /// @param previous the address prior to the current setting
  /// @param current the address of the new access-control contract
  event ConfigACSet(address indexed previous, address indexed current);

  /// @notice emitted when a new ETH withdrawal from L2 was requested
  /// @param id unique id of the published retryable transaction (keccak256(requestID, uint(0))
  /// @param amount of funds to withdraw
  event L2WithdrawalRequested(uint256 indexed id, uint256 amount, address indexed refundAddr);

  /// @param l1CrossDomainMessengerAddress address the xDomain bridge messenger (Arbitrum Inbox L1) contract address
  /// @param l2UptimeFeedAddr the L2 Flags contract address
  /// @param configACAddr address of the access controller for managing gas price on Arbitrum
  /// @param maxGas gas limit for immediate L2 execution attempt. A value around 1M should be sufficient
  /// @param gasPriceBid maximum L2 gas price to pay
  /// @param gasPriceL1FeedAddr address of the L1 gas price feed (used to approximate Arbitrum retryable ticket submission cost)
  /// @param _paymentStrategy strategy describing how the contract pays for xDomain calls
  constructor(
    address l1CrossDomainMessengerAddress,
    address l2UptimeFeedAddr,
    address configACAddr,
    uint256 maxGas,
    uint256 gasPriceBid,
    uint256 baseFee,
    address gasPriceL1FeedAddr,
    PaymentStrategy _paymentStrategy
  ) Validator(l1CrossDomainMessengerAddress, l2UptimeFeedAddr) {
    _setConfigAC(configACAddr);
    _setGasConfig(maxGas, gasPriceBid, baseFee, gasPriceL1FeedAddr);
    _setPaymentStrategy(_paymentStrategy);
  }

  /// @return stored PaymentStrategy
  function paymentStrategy() external view virtual returns (PaymentStrategy) {
    return s_paymentStrategy;
  }

  /// @return stored GasConfig
  function gasConfig() external view virtual returns (GasConfig memory) {
    return s_gasConfig;
  }

  /// @return config AccessControllerInterface contract address
  function configAC() external view virtual returns (address) {
    return address(s_configAC);
  }

  /// @notice makes this contract payable
  /// @dev receives funds:
  ///  - to use them (if configured) to pay for L2 execution on L1
  ///  - when withdrawing funds from L2 xDomain alias address (pay for L2 execution on L2)
  receive() external payable {}

  /// @notice withdraws all funds available in this contract to the msg.sender
  /// @dev only owner can call this
  function withdrawFunds() external onlyOwner {
    Address.sendValue(payable(msg.sender), address(this).balance);
  }

  /// @notice withdraws all funds available in this contract to the address specified
  /// @dev only owner can call this
  /// @param recipient address where to send the funds
  function withdrawFundsTo(address payable recipient) external onlyOwner {
    Address.sendValue(recipient, address(this).balance);
  }

  /// @notice withdraws funds from L2 xDomain alias address (representing this L1 contract)
  /// @dev only owner can call this
  /// @param amount of funds to withdraws
  /// @param refundAddr address where gas excess on L2 will be sent
  ///   WARNING: `refundAddr` is not aliased! Make sure you can recover the refunded funds on L2.
  /// @return id unique id of the published retryable transaction (keccak256(requestID, uint(0))
  function withdrawFundsFromL2(uint256 amount, address refundAddr) external onlyOwner returns (uint256 id) {
    /// Build an xDomain message to trigger the ArbSys precompile, which will create a L2 -> L1 tx transferring `amount`
    bytes memory message = abi.encodeWithSelector(ArbSys.withdrawEth.selector, address(this));

    /// Make the xDomain call
    /// NOTICE: We approximate the max submission cost of sending a retryable tx with specific calldata length.
    uint256 maxSubmissionCost = _approximateMaxSubmissionCost(message.length);
    uint256 maxGas = 120_000; // static `maxGas` for L2 -> L1 transfer
    uint256 gasPriceBid = s_gasConfig.gasPriceBid;
    uint256 l1PaymentValue = s_paymentStrategy == PaymentStrategy.L1
      ? _maxRetryableTicketCost(maxSubmissionCost, maxGas, gasPriceBid)
      : 0;

    /// NOTICE: In the case of PaymentStrategy.L2 the L2 xDomain alias address needs to be funded, as it will be paying the fee.
    id = IArbitrumDelayedInbox(L1_CROSS_DOMAIN_MESSENGER_ADDRESS).createRetryableTicketNoRefundAliasRewrite{
      value: l1PaymentValue
    }(
      ARBSYS_ADDR, /// target
      amount, /// L2 call value (requested)
      maxSubmissionCost,
      refundAddr, /// excessFeeRefundAddress
      refundAddr, /// callValueRefundAddress
      maxGas,
      gasPriceBid,
      message
    );

    /// Emits an event for the L2 withdraw request
    emit L2WithdrawalRequested(id, amount, refundAddr);

    /// Returns the ticket ID
    return id;
  }

  /// @notice sets config AccessControllerInterface contract
  /// @dev only owner can call this
  /// @param accessController new AccessControllerInterface contract address
  function setConfigAC(address accessController) external onlyOwner {
    _setConfigAC(accessController);
  }

  /// @notice sets Arbitrum gas configuration
  /// @dev access control provided by `configAC`
  /// @param maxGas gas limit for immediate L2 execution attempt. A value around 1M should be sufficient
  /// @param gasPriceBid maximum L2 gas price to pay
  /// @param gasPriceL1FeedAddr address of the L1 gas price feed (used to approximate Arbitrum retryable ticket submission cost)
  function setGasConfig(
    uint256 maxGas,
    uint256 gasPriceBid,
    uint256 baseFee,
    address gasPriceL1FeedAddr
  ) external onlyOwnerOrConfigAccess {
    _setGasConfig(maxGas, gasPriceBid, baseFee, gasPriceL1FeedAddr);
  }

  /// @notice sets the payment strategy
  /// @dev access control provided by `configAC`
  /// @param _paymentStrategy strategy describing how the contract pays for xDomain calls
  function setPaymentStrategy(PaymentStrategy _paymentStrategy) external onlyOwnerOrConfigAccess {
    _setPaymentStrategy(_paymentStrategy);
  }

  /// @notice validate method sends an xDomain L2 tx to update Flags contract, in case of change from `previousAnswer`.
  /// @dev A retryable ticket is created on the Arbitrum L1 Inbox contract. The tx gas fee can be paid from this
  ///   contract providing a value, or if no L1 value is sent with the xDomain message the gas will be paid by
  ///   the L2 xDomain alias account (generated from `address(this)`). This method is accessed controlled.
  /// @param previousAnswer previous aggregator answer
  /// @param currentAnswer new aggregator answer - value of 1 considers the service offline.
  function validate(
    uint256 /* previousRoundId */,
    int256 previousAnswer,
    uint256 /* currentRoundId */,
    int256 currentAnswer
  ) external override checkAccess returns (bool) {
    /// Avoids resending to L2 the same tx on every call
    if (previousAnswer == currentAnswer) {
      return true;
    }

    /// Encode the ArbitrumSequencerUptimeFeed call
    bytes memory message = abi.encodeWithSelector(
      SequencerUptimeFeed.updateStatus.selector,
      currentAnswer == ANSWER_SEQ_OFFLINE,
      uint64(block.timestamp)
    );

    /// Make the xDomain call
    /// NOTICE: We approximate the max submission cost of sending a retryable tx with specific calldata length.
    uint256 maxSubmissionCost = _approximateMaxSubmissionCost(message.length);
    uint256 maxGas = s_gasConfig.maxGas;
    uint256 gasPriceBid = s_gasConfig.gasPriceBid;
    uint256 l1PaymentValue = s_paymentStrategy == PaymentStrategy.L1
      ? _maxRetryableTicketCost(maxSubmissionCost, maxGas, gasPriceBid)
      : 0;

    /// NOTICE: In the case of PaymentStrategy.L2 the L2 xDomain alias address needs to be funded, as it will be paying the fee.
    /// We also ignore the returned msg number, that can be queried via the `InboxMessageDelivered` event.
    IArbitrumDelayedInbox(L1_CROSS_DOMAIN_MESSENGER_ADDRESS).createRetryableTicketNoRefundAliasRewrite{
      value: l1PaymentValue
    }(
      L2_UPTIME_FEED_ADDR, /// target
      0, /// L2 call value
      maxSubmissionCost,
      L2_ALIAS, /// excessFeeRefundAddress
      L2_ALIAS, /// callValueRefundAddress
      maxGas,
      gasPriceBid,
      message
    );

    /// return success
    return true;
  }

  /// @notice internal method that stores the payment strategy
  function _setPaymentStrategy(PaymentStrategy _paymentStrategy) internal {
    s_paymentStrategy = _paymentStrategy;
    emit PaymentStrategySet(_paymentStrategy);
  }

  /// @notice internal method that stores the gas configuration
  function _setGasConfig(uint256 maxGas, uint256 gasPriceBid, uint256 baseFee, address gasPriceL1FeedAddr) internal {
    // solhint-disable-next-line custom-errors
    require(maxGas > 0, "Max gas is zero");
    // solhint-disable-next-line custom-errors
    require(gasPriceBid > 0, "Gas price bid is zero");
    // solhint-disable-next-line custom-errors
    require(gasPriceL1FeedAddr != address(0), "Gas price Aggregator is zero address");
    s_gasConfig = GasConfig(maxGas, gasPriceBid, baseFee, gasPriceL1FeedAddr);
    emit GasConfigSet(maxGas, gasPriceBid, gasPriceL1FeedAddr);
  }

  /// @notice Internal method that stores the configuration access controller
  function _setConfigAC(address accessController) internal {
    address previousAccessController = address(s_configAC);
    if (accessController != previousAccessController) {
      s_configAC = AccessControllerInterface(accessController);
      emit ConfigACSet(previousAccessController, accessController);
    }
  }

  /// @notice Internal method that approximates the `maxSubmissionCost`
  /// @dev  This function estimates the max submission cost using the formula
  /// implemented in Arbitrum DelayedInbox's calculateRetryableSubmissionFee function
  /// @param calldataSizeInBytes xDomain message size in bytes
  function _approximateMaxSubmissionCost(uint256 calldataSizeInBytes) internal view returns (uint256) {
    return
      IArbitrumDelayedInbox(L1_CROSS_DOMAIN_MESSENGER_ADDRESS).calculateRetryableSubmissionFee(
        calldataSizeInBytes,
        s_gasConfig.baseFee
      );
  }

  /// @notice Internal helper method that calculates the total cost of the xDomain retryable ticket call
  function _maxRetryableTicketCost(
    uint256 maxSubmissionCost,
    uint256 maxGas,
    uint256 gasPriceBid
  ) internal pure returns (uint256) {
    return maxSubmissionCost + maxGas * gasPriceBid;
  }

  /// @dev reverts if the caller does not have access to change the configuration
  modifier onlyOwnerOrConfigAccess() {
    // solhint-disable-next-line custom-errors
    require(
      msg.sender == owner() || (address(s_configAC) != address(0) && s_configAC.hasAccess(msg.sender, msg.data)),
      "No access"
    );
    _;
  }
}
