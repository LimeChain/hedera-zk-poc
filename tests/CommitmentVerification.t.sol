// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {RiscZeroCheats} from "risc0/RiscZeroCheats.sol";
import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {CommitmentVerification} from "../contracts/CommitmentVerification.sol";
import {Elf} from "./Elf.sol"; // auto-generated contract after running `cargo build`.

import { Sha2Ext } from "./Sha2Ext.sol";

contract CommitmentVerificationTest is RiscZeroCheats, Test {
    CommitmentVerification public commitmentVerification;

    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();
        commitmentVerification = new CommitmentVerification(verifier);

    }

    function test_works() public {
        // mock transaction hash, just a random value
        //bytes memory leafData = "example leaf data";
        //(bytes32 b1, bytes16 b2) = Sha2Ext.sha384(leafData);
        //bytes memory leaf = abi.encode(b1, b2);
        //console2.logBytes(leaf);
        //48 bytes sha384 of b"example leaf data"
        bytes memory leaf = hex"0e70b506924f5671dca80fd1d96683258de00de70478c80700a0801c3d864186632d72ad79eb9daeec1883616fa9d2a4";

        bytes memory merkleRoot = hex"0efa1c3008184a4b9c562a787d26b2084a4c4624095cfc448c4f3c6158a32d6af0489b873c794325cf128882666bc736";


        bytes memory blsPubKey = hex"8cdd23bfd1e38ddb4ae9539f5947847bf56d3f06404d6f385758a4faa7443507e96b00da1a13d84b2fdf1a65958201352c69896103fc76a6b3c967808ad099ae";
        
        // // generated using https://iancoleman.io/blsttc_ui/
        bytes memory blsSignature = hex"a5b2ac138e13f63d947a51e0a62349ee6160013c23885252b9dde5d797008aae";

        bytes memory input = bytes.concat(merkleRoot, leaf, blsPubKey, blsSignature);

        bytes[] memory merklePath = new bytes[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory element = new bytes(48);
            assembly {
                mstore(add(add(element, 48), 0), i) // Store index value at the beginning of the bytes element
            }
            merklePath[i] = element;
            input = bytes.concat(input, merklePath[i]);

            // console2.logBytes(merklePath[i]);
        }

        //console2.logBytes(input);

        //TODO: local "cargo test" execution
        string[] memory imageRunnerInput = new string[](2);
        uint256 i = 0;
        imageRunnerInput[i++] = "cargo";
        imageRunnerInput[i++] = "test";
        // (bytes memory journal, bytes32 post_state_digest, bytes memory seal) = abi.decode(vm.ffi(imageRunnerInput), (bytes, bytes32, bytes));
        
        //Values taken from methods/receipt.json after running the "cargo test" proof generation pipeline
        bytes memory journal = hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000000300e70b506924f5671dca80fd1d96683258de00de70478c80700a0801c3d864186632d72ad79eb9daeec1883616fa9d2a40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300efa1c3008184a4b9c562a787d26b2084a4c4624095cfc448c4f3c6158a32d6af0489b873c794325cf128882666bc7360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000408cdd23bfd1e38ddb4ae9539f5947847bf56d3f06404d6f385758a4faa7443507e96b00da1a13d84b2fdf1a65958201352c69896103fc76a6b3c967808ad099ae0000000000000000000000000000000000000000000000000000000000000020a5b2ac138e13f63d947a51e0a62349ee6160013c23885252b9dde5d797008aae";
        bytes32 post_state_digest = hex"d65b764287cd4a01206a428112167afb5f151e6d029dc405cdbcd50ed299865a"; // TODO
        bytes memory seal = hex"0d7751f87b1c7b4a0e94aa5c3c7803423781382f6fcff295d1bdd7c5a5d00fd814e9e3ff881e4002958460dc6428f41aa1eefe9798da0f718112f161b2266a9217cd9efafe7824dd2d413fd2745932eab979975b5bb1adfd5a720044c1ed7d7028739915d967a79c3c63f1cf3394f9049cae98f3ef6e229b9ee50a07a4ab0137291f2321397bf0c03af599fe066b617f84b2e44a1febec04a57373efa832287d1f3a7718e59ff147195816536d882111f118ac23e7098c05b91801a4dcd5f66a2adf174695b54d489ce3c08e16e2e7c27b6bcd2ac6ab4aab79e3ed6f7b1ba0820bb226a00496a1f8437dcb3c0440c7add5ea57ffe6fafcbdf409b2cb5bf20472";
        // (bytes memory computedMerkleRoot, bytes memory computedLeaf, bytes memory computedPubkey, bytes memory computedSignature) = abi.decode(journal, (bytes, bytes, bytes, bytes));

        // require(compareBytes(computedMerkleRoot, merkleRoot), "merkle roots don't match");

        // require(compareBytes(computedLeaf, leaf), "leaf doesn't match");

        // require(compareBytes(computedPubkey, blsPubKey), "pubKey doesn't match");

        // require(compareBytes(computedSignature, blsSignature), "signature doesn't match");

        commitmentVerification.verify(journal, post_state_digest, seal);
    }
}

function compareBytes(bytes memory a, bytes memory b) pure returns (bool) {
    if(a.length != b.length) {
        return false;
    }
    for(uint i=0; i<a.length; i++) {
        if(a[i] != b[i]) {
            return false;
        }
    }
    return true;
}