// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract PrivateKeyDeriver is Test {
    function derivePrivateKey(uint256 index) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(index)));
    }

    function getPrivateKey(address addr) public returns (uint256) {
        uint256 index = 0;
        while (true) {
            uint256 pk = derivePrivateKey(index);
            address derived = vm.addr(pk);
            if (derived == addr) {
                return pk;
            }
            index++;
        }
    }
}
