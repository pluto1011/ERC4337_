// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;
import {Test, console} from "forge-std/Test.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract UserOpUtils is Test {
    function packUserOp(
        address sender,
        uint256 nonce,
        bytes memory data
    ) public pure returns (PackedUserOperation memory) {
        uint128 verificationGasLimit = 200000;
        uint128 callGasLimit = 50000;
        bytes32 gasLimits = bytes32(
            ((uint256(verificationGasLimit)) << 128) | uint256(callGasLimit)
        );

        uint256 maxPriorityFeePerGas = 1 gwei;
        uint256 maxFeePerGas = 20 gwei;
        bytes32 gasFees = bytes32(
            ((uint256(maxPriorityFeePerGas)) << 128) | uint256(maxFeePerGas)
        );

        return
            PackedUserOperation({
                sender: sender,
                nonce: nonce,
                initCode: "",
                callData: data,
                accountGasLimits: gasLimits,
                preVerificationGas: 21000,
                gasFees: gasFees,
                paymasterAndData: "",
                signature: ""
            });
    }
    function signUserOp(
        uint256 privateKey,
        bytes32 userOpHash
    ) public pure returns (bytes memory) {
        bytes32 digest = toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
    function toEthSignedMessageHash(
        bytes32 messageHash
    ) internal pure returns (bytes32 digest) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 32 is the bytes-length of messageHash
            mstore(0x1c, messageHash) // 0x1c (28) is the length of the prefix
            digest := keccak256(0x00, 0x3c) // 0x3c is the length of the prefix (0x1c) + messageHash (0x20)
        }
    }
}
