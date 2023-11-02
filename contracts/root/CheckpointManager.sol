// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ArraysUpgradeable.sol";
import "../common/Merkle.sol";
import "../interfaces/root/ICheckpointManager.sol";
import "../interfaces/common/IBLS.sol";
import "../interfaces/common/IBN256G2.sol";


contract CheckpointManager is ICheckpointManager, Initializable {
    using ArraysUpgradeable for uint256[];
    using Merkle for bytes32;

    bytes32 public constant DOMAIN = keccak256("DOMAIN_CHECKPOINT_MANAGER");

    uint256 public chainId;
    uint256 public currentEpoch;
    uint256 public currentValidatorSetLength;
    uint256 public currentCheckpointBlockNumber;
    uint256 public totalVotingPower;
    IBLS public bls;
    IBN256G2 public bn256G2;

    mapping(uint256 => Checkpoint) public checkpoints; // epochId -> root
    mapping(uint256 => Validator) public currentValidatorSet;
    uint256[] public checkpointBlockNumbers;
    bytes32 public currentValidatorSetHash;

    // Mapping to store price feed. Assuming price is represented as a uint256.
    mapping(uint256 => uint256) private priceFeeds;

    // slither-disable-next-line naming-convention
    address private immutable _INITIALIZER;

    event PriceUpdated(uint256 indexed currency, uint256 price);

    /// @notice If the contract is meant to be initialized at a later time, specifiy the address that will initialize it.
    /// @notice Otherwise, pass `address(0)`.
    constructor(address INITIALIZER) {
        // slither-disable-next-line missing-zero-check
        _INITIALIZER = INITIALIZER;
    }

    /**
     * @notice Initialization function for CheckpointManager
     * @dev Contract can only be initialized once
     * @param newBls Address of the BLS library contract
     * @param newBn256G2 Address of the BLS library contract
     * @param chainId_ Chain ID of the child chain
     */
    function initialize(
        IBLS newBls,
        IBN256G2 newBn256G2,
        uint256 chainId_,
        Validator[] calldata newValidatorSet
    ) external initializer {
        if (_INITIALIZER != address(0)) require(msg.sender == _INITIALIZER);

        // slither-disable-start events-maths
        chainId = chainId_;
        bls = newBls;
        bn256G2 = newBn256G2;
        currentValidatorSetLength = newValidatorSet.length;
        _setNewValidatorSet(newValidatorSet);
        // slither-disable-end events-maths
    }

    /**
     * @inheritdoc ICheckpointManager
     */
    function submit(
        CheckpointMetadata calldata checkpointMetadata,
        Checkpoint calldata checkpoint,
        uint256[2] calldata signature,
        Validator[] calldata newValidatorSet,
        bytes calldata bitmap,
        BatchFeedInput[] calldata feedInputs
    ) external {
        require(currentValidatorSetHash == checkpointMetadata.currentValidatorSetHash, "INVALID_VALIDATOR_SET_HASH");
        bytes memory hash = abi.encode(
            keccak256(
                abi.encode(
                    chainId,
                    checkpoint.blockNumber,
                    checkpointMetadata.blockHash,
                    checkpointMetadata.blockRound,
                    checkpoint.epoch,
                    checkpoint.eventRoot,
                    checkpointMetadata.currentValidatorSetHash,
                    keccak256(abi.encode(feedInputs)),
                    keccak256(abi.encode(newValidatorSet))
                )
            )
        );

        _verifySignature(bls.hashToPoint(DOMAIN, hash), signature, bitmap);

        uint256 prevEpoch = currentEpoch;

        _verifyCheckpoint(prevEpoch, checkpoint);

        checkpoints[checkpoint.epoch] = checkpoint;

        if (checkpoint.epoch > prevEpoch) {
            // if new epoch, push new end block
            checkpointBlockNumbers.push(checkpoint.blockNumber);
            ++currentEpoch;
        } else {
            // update last end block if updating event root for epoch
            checkpointBlockNumbers[checkpointBlockNumbers.length - 1] = checkpoint.blockNumber;
        }

        currentCheckpointBlockNumber = checkpoint.blockNumber;

        _updateFeeds(feedInputs, checkpoint.eventRoot);

        _setNewValidatorSet(newValidatorSet);
    }

    function _updateFeeds(BatchFeedInput[] calldata inputs, bytes32 eventRoot) private {
        uint256 length = inputs.length;
        for (uint256 i = 0; i < length; i++) {
            _updateSingleFeed(inputs[i].leafIndex, inputs[i].unhashedLeaf, inputs[i].proof, eventRoot);
        }
    }

    function _updateSingleFeed(
        uint256 leafIndex,
        bytes calldata unhashedLeaf,
        bytes32[] calldata proof,
        bytes32 eventRoot
    ) private {
        require(
            keccak256(unhashedLeaf).checkMembership(leafIndex, eventRoot, proof),
            // _verifyEventMembershipByBlockNumber(blockNumber, keccak256(unhashedLeaf), leafIndex, proof),
            "INVALID_PROOF"
        );

        // Assuming data contains the currency symbol (as bytes32) followed by its price (as uint256).
        (uint256 currency, uint256 price) = abi.decode(unhashedLeaf, (uint256, uint256));

        priceFeeds[currency] = price;

        emit PriceUpdated(currency, price);
    }

    // remove after merkle-proof verifcation moves outside of this contract
    function _verifyEventMembershipByBlockNumber(
        uint256 blockNumber,
        bytes32 leaf,
        uint256 leafIndex,
        bytes32[] calldata proof
    ) private view returns (bool) {
        bytes32 eventRoot = getEventRootByBlock(blockNumber);
        require(eventRoot != bytes32(0), "NO_EVENT_ROOT_FOR_BLOCK_NUMBER");
        return leaf.checkMembership(leafIndex, eventRoot, proof);
    }

    /**
     * @inheritdoc ICheckpointManager
     */
    function getEventMembershipByBlockNumber(
        uint256 blockNumber,
        bytes32 leaf,
        uint256 leafIndex,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 eventRoot = getEventRootByBlock(blockNumber);
        require(eventRoot != bytes32(0), "NO_EVENT_ROOT_FOR_BLOCK_NUMBER");
        return leaf.checkMembership(leafIndex, eventRoot, proof);
    }

    /**
     * @inheritdoc ICheckpointManager
     */
    function getEventMembershipByEpoch(
        uint256 epoch,
        bytes32 leaf,
        uint256 leafIndex,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 eventRoot = checkpoints[epoch].eventRoot;
        require(eventRoot != bytes32(0), "NO_EVENT_ROOT_FOR_EPOCH");
        return leaf.checkMembership(leafIndex, eventRoot, proof);
    }

    /**
     * @inheritdoc ICheckpointManager
     */
    function getCheckpointBlock(uint256 blockNumber) external view returns (bool, uint256) {
        uint256 checkpointBlockIdx = checkpointBlockNumbers.findUpperBound(blockNumber);
        if (checkpointBlockIdx == checkpointBlockNumbers.length) {
            return (false, 0);
        }
        return (true, checkpointBlockNumbers[checkpointBlockIdx]);
    }

    /**
     * @inheritdoc ICheckpointManager
     */
    function getEventRootByBlock(uint256 blockNumber) public view returns (bytes32) {
        return checkpoints[checkpointBlockNumbers.findUpperBound(blockNumber) + 1].eventRoot;
    }

    function getPrice(uint256 _pairIndex) external view returns (uint256, bool) {
        bool flag;
        uint256 res = priceFeeds[_pairIndex];

        if (res == 0) {
            flag = false;
        } else {
            flag = true;
        }

        return (res, flag);
    }

    function getPrices(
        uint256[] memory _pairIndexes
    ) external view returns (uint256[] memory, bool[] memory) {
            bool[] memory flags = new bool[](_pairIndexes.length);
            uint256[] memory prices = new uint256[](_pairIndexes.length);

            for (uint256 i = 0; i < _pairIndexes.length; i++) {

                uint256 price = priceFeeds[_pairIndexes[i]];

                if (price == 0) {
                    flags[i] = false;
                } else {
                    flags[i] = true;
                }

                prices[i] = price;
            }

        return (prices, flags);
    }



    function _setNewValidatorSet(Validator[] calldata newValidatorSet) private {
        uint256 length = newValidatorSet.length;
        currentValidatorSetLength = length;
        currentValidatorSetHash = keccak256(abi.encode(newValidatorSet));
        uint256 totalPower = 0;
        for (uint256 i = 0; i < length; ++i) {
            uint256 votingPower = newValidatorSet[i].votingPower;
            require(votingPower > 0, "VOTING_POWER_ZERO");
            totalPower += votingPower;
            currentValidatorSet[i] = newValidatorSet[i];
        }
        totalVotingPower = totalPower;
    }

    /**
     * @notice Internal function that asserts that the signature is valid and that the required threshold is met
     * @param message The message that was signed by validators (i.e. checkpoint hash)
     * @param signature The aggregated signature submitted by the proposer
     */
    function _verifySignature(
        uint256[2] memory message,
        uint256[2] calldata signature,
        bytes calldata bitmap
    ) private view {
        uint256 length = currentValidatorSetLength;
        // slither-disable-next-line uninitialized-local
        uint256[4] memory aggPubkey;
        uint256 aggVotingPower = 0;
        for (uint256 i = 0; i < length; ) {
            if (_getValueFromBitmap(bitmap, i)) {
                if (aggVotingPower == 0) {
                    aggPubkey = currentValidatorSet[i].blsKey;
                } else {
                    uint256[4] memory blsKey = currentValidatorSet[i].blsKey;
                    // slither-disable-next-line calls-loop
                    (aggPubkey[0], aggPubkey[1], aggPubkey[2], aggPubkey[3]) = bn256G2.ecTwistAdd(
                        aggPubkey[0],
                        aggPubkey[1],
                        aggPubkey[2],
                        aggPubkey[3],
                        blsKey[0],
                        blsKey[1],
                        blsKey[2],
                        blsKey[3]
                    );
                }
                aggVotingPower += currentValidatorSet[i].votingPower;
            }
            unchecked {
                ++i;
            }
        }

        require(aggVotingPower != 0, "BITMAP_IS_EMPTY");
        require(aggVotingPower > ((2 * totalVotingPower) / 3), "INSUFFICIENT_VOTING_POWER");

        (bool callSuccess, bool result) = bls.verifySingle(signature, aggPubkey, message);

        require(callSuccess && result, "SIGNATURE_VERIFICATION_FAILED");
    }

    /**
     * @notice Internal function that performs checks on the checkpoint
     * @param prevId Current checkpoint ID
     * @param checkpoint The checkpoint to store
     */
    function _verifyCheckpoint(uint256 prevId, Checkpoint calldata checkpoint) private view {
        Checkpoint memory oldCheckpoint = checkpoints[prevId];
        require(
            checkpoint.epoch == oldCheckpoint.epoch || checkpoint.epoch == (oldCheckpoint.epoch + 1),
            "INVALID_EPOCH"
        );
        require(checkpoint.blockNumber > oldCheckpoint.blockNumber, "EMPTY_CHECKPOINT");
    }

    function _getValueFromBitmap(bytes calldata bitmap, uint256 index) private pure returns (bool) {
        uint256 byteNumber = index / 8;
        uint8 bitNumber = uint8(index % 8);

        if (byteNumber >= bitmap.length) {
            return false;
        }

        // Get the value of the bit at the given 'index' in a byte.
        return uint8(bitmap[byteNumber]) & (1 << bitNumber) > 0;
    }

    // slither-disable-next-line unused-state,naming-convention
    uint256[50] private __gap;


}
