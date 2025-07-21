// SPDX-FileCopyrightText: 2025 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.24;

import { AccessControlEnumerable } from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";

import { AssetRecoverer } from "./abstract/AssetRecoverer.sol";
import { ExitTypes } from "./abstract/ExitTypes.sol";

import { PausableUntil } from "./lib/utils/PausableUntil.sol";
import { SigningKeys } from "./lib/SigningKeys.sol";

import { ICSEjector } from "./interfaces/ICSEjector.sol";
import { ICSModule } from "./interfaces/ICSModule.sol";
import { ITriggerableWithdrawalsGateway, ValidatorData } from "./interfaces/ITriggerableWithdrawalsGateway.sol";

contract CSEjector is
    ICSEjector,
    ExitTypes,
    AccessControlEnumerable,
    PausableUntil,
    AssetRecoverer
{
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant RESUME_ROLE = keccak256("RESUME_ROLE");
    bytes32 public constant RECOVERER_ROLE = keccak256("RECOVERER_ROLE");

    uint256 public immutable STAKING_MODULE_ID;
    ICSModule public immutable MODULE;
    address public immutable STRIKES;

    modifier onlyStrikes() {
        if (msg.sender != STRIKES) {
            revert SenderIsNotStrikes();
        }

        _;
    }

    constructor(
        address module,
        address strikes,
        uint256 stakingModuleId,
        address admin
    ) {
        if (module == address(0)) {
            revert ZeroModuleAddress();
        }
        if (strikes == address(0)) {
            revert ZeroStrikesAddress();
        }
        if (admin == address(0)) {
            revert ZeroAdminAddress();
        }

        STRIKES = strikes;
        MODULE = ICSModule(module);
        STAKING_MODULE_ID = stakingModuleId;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @inheritdoc ICSEjector
    function resume() external onlyRole(RESUME_ROLE) {
        _resume();
    }

    /// @inheritdoc ICSEjector
    function pauseFor(uint256 duration) external onlyRole(PAUSE_ROLE) {
        _pauseFor(duration);
    }

    /// @inheritdoc ICSEjector
    function voluntaryEject(
        uint256 nodeOperatorId,
        uint256 startFrom,
        uint256 keysCount,
        address refundRecipient
    ) external payable whenResumed { //@audit user entry point
        //@audit-info validates the node operator is same as the msg.sender of the function call
        _onlyNodeOperatorOwner(nodeOperatorId);
        {
            // A key must be deposited to prevent ejecting unvetted keys that can intersect with
            // other modules.
            //@audit-info calculate the maximum key index
            uint256 maxKeyIndex = startFrom + keysCount;
            if (
                //@audit-info checks if the maximum key index is greater than the total deposited keys for the node operator
                maxKeyIndex >
                MODULE.getNodeOperatorTotalDepositedKeys(nodeOperatorId)
            ) {
                //@audit-info reverts an error if true
                revert SigningKeysInvalidOffset();
            }
            // A key must be non-withdrawn to restrict unlimited exit requests consuming sanity
            // checker limits, although a deposited key can be requested to exit multiple times.
            // But, it will eventually be withdrawn, so potentially malicious behaviour stops when
            // there are no active keys available
            //@audit-info loops through all the keys and checks if they are withdrawn within the node operator
            for (uint256 i = startFrom; i < maxKeyIndex; ++i) {

                if (MODULE.isValidatorWithdrawn(nodeOperatorId, i)) {
                    









                }
            }
        }
        //@audit-info retrieves a certain public key from the node operator starting from a specified index 
        bytes memory pubkeys = MODULE.getSigningKeys(
            nodeOperatorId,
            startFrom,
            keysCount
        );

        //@audit-info crates an object to hold an array of validator data with specified length
        ValidatorData[] memory exitsData = new ValidatorData[](keysCount);
        for (uint256 i; i < keysCount; ++i) {
            bytes memory pubkey = new bytes(SigningKeys.PUBKEY_LENGTH);
            assembly {
                let keyLen := mload(pubkey) // PUBKEY_LENGTH
                let offset := mul(keyLen, i) // PUBKEY_LENGTH * i
                let keyPos := add(add(pubkeys, 0x20), offset) // pubkeys[offset]
                mcopy(add(pubkey, 0x20), keyPos, keyLen) // pubkey = pubkeys[offset:offset+PUBKEY_LENGTH]
            }
            exitsData[i] = ValidatorData({
                stakingModuleId: STAKING_MODULE_ID,
                nodeOperatorId: nodeOperatorId,
                pubkey: pubkey
            });
        }

        // @dev This call might revert if the limits are exceeded on the protocol side.
        triggerableWithdrawalsGateway().triggerFullWithdrawals{
            value: msg.value
        }(
            exitsData,
            refundRecipient == address(0) ? msg.sender : refundRecipient,
            VOLUNTARY_EXIT_TYPE_ID
        );
    }

    /// @dev Additional method for non-sequential keys to save gas and decrease fee amount compared
    /// to separate transactions.
    /// @inheritdoc ICSEjector
    function voluntaryEjectByArray(
        uint256 nodeOperatorId,
        uint256[] calldata keyIndices,
        address refundRecipient
    ) external payable whenResumed {//@audit user entry point
        //@audit-info validates the node operator is same as the msg.sender of the function call
        _onlyNodeOperatorOwner(nodeOperatorId);
        //@audit-info stores the total deposited keys for the node operator
        uint256 totalDepositedKeys = MODULE.getNodeOperatorTotalDepositedKeys(
            nodeOperatorId
        );
        //@audit-info initialises an array of validator data type with the length of key indices
        ValidatorData[] memory exitsData = new ValidatorData[](
            keyIndices.length
        );
        //@audit-info loops through the key indices and checks if they are valid by seeing if any key index is greater than the total deposited keys
        for (uint256 i = 0; i < keyIndices.length; i++) {
            // A key must be deposited to prevent ejecting unvetted keys that can intersect with
            // other modules.
            //@audit-info reverts an error if the key index is greater than the total deposited keys
            if (keyIndices[i] >= totalDepositedKeys) {
                revert SigningKeysInvalidOffset();
            }
            // A key must be non-withdrawn to restrict unlimited exit requests consuming sanity
            // checker limits, although a deposited key can be requested to exit multiple times.
            // But, it will eventually be withdrawn, so potentially malicious behaviour stops when
            // there are no active keys available
            //@audit-info reverts an error if the current key index is already withdrawn
            if (MODULE.isValidatorWithdrawn(nodeOperatorId, keyIndices[i])) {
                revert AlreadyWithdrawn();
            }
            //@audit-info gets a public key for the current key index in the specific node operator
            bytes memory pubkey = MODULE.getSigningKeys(
                nodeOperatorId,
                keyIndices[i],
                1
            );
            //@audit-info assisgns the validator data of stakingmodule id, node operator id and public key to the exits data array
            exitsData[i] = ValidatorData({
                stakingModuleId: STAKING_MODULE_ID,
                nodeOperatorId: nodeOperatorId,
                pubkey: pubkey
            });
        }

        // @dev This call might revert if the limits are exceeded on the protocol side.
        triggerableWithdrawalsGateway().triggerFullWithdrawals{
            value: msg.value
        }(
            exitsData,
            refundRecipient == address(0) ? msg.sender : refundRecipient,
            VOLUNTARY_EXIT_TYPE_ID
        );
    }

    /// @inheritdoc ICSEjector
    function ejectBadPerformer(
        uint256 nodeOperatorId,
        uint256 keyIndex,
        address refundRecipient
    ) external payable whenResumed onlyStrikes {
        // A key must be deposited to prevent ejecting unvetted keys that can intersect with
        // other modules.
        if (
            keyIndex >= MODULE.getNodeOperatorTotalDepositedKeys(nodeOperatorId)
        ) {
            revert SigningKeysInvalidOffset();
        }
        // A key must be non-withdrawn to restrict unlimited exit requests consuming sanity checker
        // limits, although a deposited key can be requested to exit multiple times. But, it will
        // eventually be withdrawn, so potentially malicious behaviour stops when there are no
        // active keys available
        if (MODULE.isValidatorWithdrawn(nodeOperatorId, keyIndex)) {
            revert AlreadyWithdrawn();
        }

        ValidatorData[] memory exitsData = new ValidatorData[](1);
        bytes memory pubkey = MODULE.getSigningKeys(
            nodeOperatorId,
            keyIndex,
            1
        );
        exitsData[0] = ValidatorData({
            stakingModuleId: STAKING_MODULE_ID,
            nodeOperatorId: nodeOperatorId,
            pubkey: pubkey
        });

        // @dev This call might revert if the limits are exceeded on the protocol side.
        triggerableWithdrawalsGateway().triggerFullWithdrawals{
            value: msg.value
        }(exitsData, refundRecipient, STRIKES_EXIT_TYPE_ID);
    }

    /// @inheritdoc ICSEjector
    function triggerableWithdrawalsGateway()
        public
        view
        returns (ITriggerableWithdrawalsGateway)
    {
        return
            ITriggerableWithdrawalsGateway(
                MODULE.LIDO_LOCATOR().triggerableWithdrawalsGateway()
            );
    }

    /// @dev Verifies that the sender is the owner of the node operator
    function _onlyNodeOperatorOwner(uint256 nodeOperatorId) internal view {
        address owner = MODULE.getNodeOperatorOwner(nodeOperatorId);
        if (owner == address(0)) {
            revert NodeOperatorDoesNotExist();
        }
        if (owner != msg.sender) {
            revert SenderIsNotEligible();
        }
    }

    function _onlyRecoverer() internal view override {
        _checkRole(RECOVERER_ROLE);
    }
}
