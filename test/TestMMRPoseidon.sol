// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

import {MMRPoseidon2} from "../src/MMRPoseidon2.sol";
import {Field} from "@poseidon2/src/Field.sol";
import {Poseidon2Yul} from "@poseidon2/src/Poseidon2Yul.sol";

/**
 * I wrote this solidity test file just to show how to use this library
 * More detail test cases are written in javascript. Please see TestMMR.js
 */
contract TestMMRPoseidon is Test {
    using MMRPoseidon2 for MMRPoseidon2.Tree;
    MMRPoseidon2.Tree mmr;

    /**
     * Helper function to hash data using Poseidon2
     */
    function hashData(bytes memory _data) internal pure returns (bytes32) {
        bytes32 data = keccak256(_data);
        return data;
    }

    /**
     * Appending 10 items will construct a Merkle Mountain Range like below
     *              15
     *       7             14
     *    3      6     10       13       18
     *  1  2   4  5   8  9    11  12   16  17
     */
    function testPoseidonMountainRange() public {
        // wire the Poseidon2 hasher (staticcall target) before any append
        Poseidon2Yul yul = new Poseidon2Yul();
        mmr.setHasher(address(yul));

        // Hash data before appending (MMR expects pre-hashed values)
        mmr.append(hashData("0x0001")); // stored at index 1
        mmr.append(hashData("0x0002")); // stored at index 2
        mmr.append(hashData("0x0003")); // stored at index 4
        mmr.append(hashData("0x0004")); // stored at index 5
        mmr.append(hashData("0x0005")); // stored at index 8
        mmr.append(hashData("0x0006")); // stored at index 9
        mmr.append(hashData("0x0007")); // stored at index 11
        mmr.append(hashData("0x0008")); // stored at index 12
        mmr.append(hashData("0x0009")); // stored at index 16
        mmr.append(hashData("0x000a")); // stored at index 17

        uint256 index = 17;

        // Get a merkle proof for index 17
        (bytes32 root, uint256 width, bytes32[] memory peaks, bytes32[] memory siblings) = mmr.getMerkleProof(index);

        console.log("\n=== Proof ===");
        console.logBytes32(root);

        console.log(width);

        console.log("Peaks:");
        for (uint256 i = 0; i < peaks.length; i++) {
            console.logBytes32(peaks[i]);
        }

        console.log("Siblings:");
        for (uint256 i = 0; i < siblings.length; i++) {
            console.logBytes32(siblings[i]);
        }

        // Hash the value that was originally appended
        bytes32 valueHash = hashData("0x000a");

        // using MMR library verify the root includes the leaf
        assertTrue(
            MMRPoseidon2.verifyInclusion(address(yul), root, width, index, valueHash, peaks, siblings),
            "should return true or reverted"
        );
    }
}
