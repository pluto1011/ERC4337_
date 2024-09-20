// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SimpleAccount} from "../src/SimpleAccount.sol";
import {SimpleAccountV2} from "../src/SimpleAccountV2.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ERC1967Proxy} from "../lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Counter} from "../src/Counter.sol";
import {UserOpUtils} from "./UserOpUtils.sol";

contract SimpleAccountTest is Test {
    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    EntryPoint public entryPoint;
    SimpleAccount public simpleAccountImpl;
    SimpleAccountV2 public simpleAccountV2Impl;
    Counter public counter;
    UserOpUtils public utils;

    uint256 public ownerPrivateKey = 1;
    address public owner;
    address public bob;
    address public beneficiary;

    event SimpleAccountInitialized(
        IEntryPoint indexed entryPoint,
        address indexed owner
    );

    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    function setUp() public {
        owner = vm.addr(ownerPrivateKey);
        vm.label(owner, "Owner");
        vm.deal(owner, 100 ether);

        bob = makeAddr("bob");
        vm.label(bob, "Bob");

        beneficiary = makeAddr("beneficiary");
        vm.label(beneficiary, "Beneficiary");
        vm.deal(beneficiary, 1 ether);

        entryPoint = new EntryPoint();
        vm.label(address(entryPoint), "EntryPoint");

        simpleAccountImpl = new SimpleAccount(entryPoint);
        vm.label(address(simpleAccountImpl), "SimpleAccountImpl");

        simpleAccountV2Impl = new SimpleAccountV2(entryPoint);
        vm.label(address(simpleAccountV2Impl), "SimpleAccountV2Impl");

        counter = new Counter();
        vm.label(address(counter), "Counter");

        utils = new UserOpUtils();
    }

    function test_Deploy() public {
        bytes memory data = abi.encodeWithSelector(
            simpleAccountImpl.initialize.selector,
            owner
        );

        vm.expectEmit(true, true, true, true);
        emit SimpleAccountInitialized(entryPoint, owner);

        vm.prank(owner);
        ERC1967Proxy simpleAccountProxy = new ERC1967Proxy( //*동작
            address(simpleAccountImpl),
            data
        );

        // read the implementation address from the proxy contract //*검증 이 패턴을 따르고 있음.
        address impl = address(
            uint160(
                uint256(
                    vm.load(address(simpleAccountProxy), IMPLEMENTATION_SLOT)
                )
            )
        );

        assertEq(impl, address(simpleAccountImpl));

        SimpleAccount simpleAccount = SimpleAccount(
            payable(address(simpleAccountProxy))
        );

        assertEq(simpleAccount.owner(), owner);
        assertEq(address(simpleAccount.entryPoint()), address(entryPoint));
    }
    function test_ValidateUserOp() public {
        SimpleAccount simpleAccount = createAccount();

        PackedUserOperation memory packedUserOp = utils.packUserOp(
            address(simpleAccount),
            simpleAccount.getNonce(),
            ""
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(packedUserOp);

        bytes memory signature = utils.signUserOp(ownerPrivateKey, userOpHash); //! 이게 없네

        packedUserOp.signature = signature;

        uint256 missingAccountFunds = 10 gwei;
        uint256 accountBalanceBefore = address(simpleAccount).balance;

        vm.prank(address(entryPoint)); //* 원래는 번들러가 entgrypoint에다가 쏘는 거긴 한데.
        uint256 validationData = simpleAccount.validateUserOp(
            packedUserOp,
            userOpHash,
            missingAccountFunds
        );

        assertEq(validationData, 0);
        assertEq(address(entryPoint).balance, missingAccountFunds);
        assertEq(
            address(simpleAccount).balance,
            accountBalanceBefore - missingAccountFunds
        );
    }

    function createAccount() public returns (SimpleAccount) {
        bytes memory data = abi.encodeWithSelector(
            simpleAccountImpl.initialize.selector,
            owner
        );

        vm.prank(owner);
        ERC1967Proxy simpleAccountProxy = new ERC1967Proxy(
            address(simpleAccountImpl),
            data
        );
        vm.deal(address(simpleAccountProxy), 1 ether);

        return SimpleAccount(payable(address(simpleAccountProxy)));
        //? simpeAccount가 인터페이스가 아닐텐데 코드가 같으면 타입 변환이 가능해??
    }

    function test_HandleOps() public {
        SimpleAccount simpleAccount = createAccount();

        bytes memory callData = abi.encodeWithSelector(
            SimpleAccount.execute.selector,
            address(counter),
            0,
            abi.encodeWithSelector(counter.increment.selector)
        );

        uint256 nonce = simpleAccount.getNonce();

        PackedUserOperation memory packedUserOp = utils.packUserOp(
            address(simpleAccount),
            nonce,
            callData
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(packedUserOp);

        bytes memory signature = utils.signUserOp(ownerPrivateKey, userOpHash);

        packedUserOp.signature = signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = packedUserOp;

        uint256 counterBefore = counter.number();
        uint256 accountBalanceBefore = address(simpleAccount).balance;
        uint256 beneficiaryBalanceBefore = beneficiary.balance;

        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(
            userOpHash,
            address(simpleAccount),
            address(0),
            nonce,
            true,
            0,
            0
        );

        entryPoint.handleOps(ops, payable(beneficiary));

        assertEq(counter.number(), counterBefore + 1);
        assertLt(address(simpleAccount).balance, accountBalanceBefore);
        assertGt(beneficiary.balance, beneficiaryBalanceBefore);
    }
    function test_HandleOpsWithFailedOp() public {
        SimpleAccount simpleAccount = createAccount();

        bytes memory callData = abi.encodeWithSelector(
            SimpleAccount.execute.selector,
            address(counter),
            0,
            abi.encodeWithSignature("decrement()")
        ); // call a non-existent function

        uint256 nonce = simpleAccount.getNonce();

        PackedUserOperation memory packedUserOp = utils.packUserOp(
            address(simpleAccount),
            nonce,
            callData
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(packedUserOp);

        bytes memory signature = utils.signUserOp(ownerPrivateKey, userOpHash);

        packedUserOp.signature = signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = packedUserOp;

        uint256 counterBefore = counter.number();
        uint256 accountBalanceBefore = address(simpleAccount).balance;
        uint256 beneficiaryBalanceBefore = beneficiary.balance;

        bool success = false;

        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(
            userOpHash,
            address(simpleAccount),
            address(0),
            nonce,
            success,
            0,
            0
        );

        entryPoint.handleOps(ops, payable(beneficiary));

        assertEq(counter.number(), counterBefore);
        assertLt(address(simpleAccount).balance, accountBalanceBefore);
        assertGt(beneficiary.balance, beneficiaryBalanceBefore);
    }
}
