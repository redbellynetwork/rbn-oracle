// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {AggregatorV2V3Interface} from "../../shared/interfaces/AggregatorV2V3Interface.sol";
import {AggregatorV3Interface} from "../../shared/interfaces/AggregatorV3Interface.sol";
import {TypeAndVersionInterface} from "../../interfaces/TypeAndVersionInterface.sol";
import {AggregatorInterface} from "../../shared/interfaces/AggregatorInterface.sol";

import {SimpleReadAccessController} from "../../shared/access/SimpleReadAccessController.sol";

/// @title ScrollSequencerUptimeFeed - L2 sequencer uptime status aggregator
/// @notice L2 contract that receives status updates, and records a new answer if the status changed
abstract contract SequencerUptimeFeed is AggregatorV2V3Interface, TypeAndVersionInterface, SimpleReadAccessController {
  /// @dev Round info (for uptime history)
  struct Round {
    bool status;
    uint64 startedAt;
    uint64 updatedAt;
  }

  /// @dev Packed state struct to save sloads
  struct FeedState {
    uint80 latestRoundId;
    bool latestStatus;
    uint64 startedAt;
    uint64 updatedAt;
  }

  /// @notice Sender is not the L2 messenger
  error InvalidSender();
  /// @notice Replacement for AggregatorV3Interface "No data present"
  error NoDataPresent();

  event L1SenderTransferred(address indexed from, address indexed to);
  /// @dev Emitted when an `updateStatus` call is ignored due to unchanged status or stale timestamp
  event UpdateIgnored(bool latestStatus, uint64 latestTimestamp, bool incomingStatus, uint64 incomingTimestamp);
  /// @dev Emitted when a updateStatus is called without the status changing
  event RoundUpdated(int256 status, uint64 updatedAt);

  // solhint-disable-next-line chainlink-solidity/all-caps-constant-storage-variables
  uint8 public constant override decimals = 0;
  // solhint-disable-next-line chainlink-solidity/all-caps-constant-storage-variables
  string public constant override description = "L2 Sequencer Uptime Status Feed";
  // solhint-disable-next-line chainlink-solidity/all-caps-constant-storage-variables
  uint256 public constant override version = 1;

  /// @dev L1 address
  address private s_l1Sender;

  /// @dev s_latestRoundId == 0 means this contract is uninitialized.
  FeedState private s_feedState = FeedState({latestRoundId: 0, latestStatus: false, startedAt: 0, updatedAt: 0});

  /// @dev mapping of round ID to round data
  mapping(uint80 roundId => Round round) private s_rounds;

  /// @param l1SenderAddress Address of the L1 contract that is permissioned to call this contract
  /// @param initialStatus The initial status of the feed
  constructor(address l1SenderAddress, bool initialStatus) {
    _setL1Sender(l1SenderAddress);

    // Initialise roundId == 1 as the first round
    _recordRound(1, initialStatus, uint64(block.timestamp));
  }

  /// @notice Should return true if the sender is not authorized to call `updateStatus`
  function _isNotValidSender() internal view virtual returns (bool);

  /// @notice Check if a roundId is valid in this current contract state
  /// @dev Mainly used for AggregatorV2V3Interface functions
  /// @param roundId Round ID to check
  function _isValidRound(uint256 roundId) private view returns (bool) {
    return roundId > 0 && roundId <= type(uint80).max && s_feedState.latestRoundId >= roundId;
  }

  /// @return L1 sender address
  function l1Sender() public view virtual returns (address) {
    return s_l1Sender;
  }

  /// @notice Set the allowed L1 sender for this contract to a new L1 sender
  /// @dev Can be disabled by setting the L1 sender as `address(0)`. Accessible only by owner.
  /// @param to new L1 sender that will be allowed to call `updateStatus` on this contract
  function transferL1Sender(address to) external virtual onlyOwner {
    _setL1Sender(to);
  }

  /// @notice internal method that stores the L1 sender
  function _setL1Sender(address to) private {
    address from = s_l1Sender;
    if (from != to) {
      s_l1Sender = to;
      emit L1SenderTransferred(from, to);
    }
  }

  /// @dev Returns an AggregatorV2V3Interface compatible answer from status flag
  /// @param status The status flag to convert to an aggregator-compatible answer
  function _getStatusAnswer(bool status) private pure returns (int256) {
    return status ? int256(1) : int256(0);
  }

  /// @notice Helper function to record a round and set the latest feed state.
  /// @param roundId The round ID to record
  /// @param status Sequencer status
  /// @param timestamp The L1 block timestamp of status update
  function _recordRound(uint80 roundId, bool status, uint64 timestamp) private {
    s_feedState = FeedState(roundId, status, timestamp, uint64(block.timestamp));
    s_rounds[roundId] = Round(status, timestamp, uint64(block.timestamp));

    emit NewRound(roundId, msg.sender, timestamp);
    emit AnswerUpdated(_getStatusAnswer(status), roundId, timestamp);
  }

  /// @notice Helper function to update when a round was last updated
  /// @param roundId The round ID to update
  /// @param status Sequencer status
  function _updateRound(uint80 roundId, bool status) private {
    s_feedState.updatedAt = uint64(block.timestamp);
    s_rounds[roundId].updatedAt = uint64(block.timestamp);
    emit RoundUpdated(_getStatusAnswer(status), uint64(block.timestamp));
  }

  /// @notice Record a new status and timestamp if it has changed since the last round.
  /// @dev This function will revert if not called from `l1Sender` via the L1->L2 messenger.
  ///
  /// @param status Sequencer status
  /// @param timestamp Block timestamp of status update
  function updateStatus(bool status, uint64 timestamp) external {
    if (_isNotValidSender()) {
      revert InvalidSender();
    }

    FeedState memory feedState = s_feedState;

    // Ignore if latest recorded timestamp is newer
    if (feedState.startedAt > timestamp) {
      emit UpdateIgnored(feedState.latestStatus, feedState.startedAt, status, timestamp);
      return;
    }

    if (feedState.latestStatus == status) {
      _updateRound(feedState.latestRoundId, status);
    } else {
      feedState.latestRoundId += 1;
      _recordRound(feedState.latestRoundId, status, timestamp);
    }
  }

  /// @inheritdoc AggregatorInterface
  function latestAnswer() external view override checkAccess returns (int256) {
    return _getStatusAnswer(s_feedState.latestStatus);
  }

  /// @inheritdoc AggregatorInterface
  function latestTimestamp() external view override checkAccess returns (uint256) {
    return s_feedState.startedAt;
  }

  /// @inheritdoc AggregatorInterface
  function latestRound() external view override checkAccess returns (uint256) {
    return s_feedState.latestRoundId;
  }

  /// @inheritdoc AggregatorInterface
  function getAnswer(uint256 roundId) external view override checkAccess returns (int256) {
    if (!_isValidRound(roundId)) {
      revert NoDataPresent();
    }

    return _getStatusAnswer(s_rounds[uint80(roundId)].status);
  }

  /// @inheritdoc AggregatorInterface
  function getTimestamp(uint256 roundId) external view override checkAccess returns (uint256) {
    if (!_isValidRound(roundId)) {
      revert NoDataPresent();
    }

    return s_rounds[uint80(roundId)].startedAt;
  }

  /// @inheritdoc AggregatorV3Interface
  function getRoundData(
    uint80 _roundId
  )
    public
    view
    override
    checkAccess
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
  {
    if (!_isValidRound(_roundId)) {
      revert NoDataPresent();
    }

    Round memory round = s_rounds[_roundId];

    return (_roundId, _getStatusAnswer(round.status), uint256(round.startedAt), uint256(round.updatedAt), _roundId);
  }

  /// @inheritdoc AggregatorV3Interface
  function latestRoundData()
    external
    view
    override
    checkAccess
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
  {
    FeedState memory feedState = s_feedState;

    return (
      feedState.latestRoundId,
      _getStatusAnswer(feedState.latestStatus),
      feedState.startedAt,
      feedState.updatedAt,
      feedState.latestRoundId
    );
  }
}