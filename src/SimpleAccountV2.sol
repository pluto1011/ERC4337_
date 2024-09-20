// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {SimpleAccount} from "./SimpleAccount.sol";

contract SimpleAccountV2 is SimpleAccount {
    constructor(IEntryPoint entryPoint_) SimpleAccount(entryPoint_) {}

    function version() external pure virtual override returns (string memory) {
        return "2.0.0";
    }
}
