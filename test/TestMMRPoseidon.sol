// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";

import {MMRPoseidon2} from "../src/MMRPoseidon2.sol";
import {Field} from "@poseidon2/src/bn254/solidity/Field.sol";
import {IPoseidon2} from "@poseidon2/src/IPoseidon2.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

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
    // Pin the deployed hasher to reference vectors confirmed against bb.js 0.87.0 and
    // the zkpassport poseidon2 JS lib (the values the Noir circuit and the SDK compute).
    // The overflow pair is one that poseidon2-evm v1 miscomputed on-chain.
    function testHasherMatchesReferenceVectors() public {
        IPoseidon2 yul = IPoseidon2(address(new Poseidon2Yul()));

        assertEq(
            yul.hash_2(1, 2), 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383, "hash_2(1,2) mismatch"
        );
        assertEq(
            yul.hash_2(
                0x0ea68260555db0a15e381a0e31b3b136f1aa87d51b87171fbec592c5cd190860,
                0x2f8b73698adc283b213b14f304380eaaf912dbf9953e40b3c32265418912db3f
            ),
            0x1f4cd28f103c76eaaccdebf2415d1abe812460283221e4ffb82863ab397cfed5,
            "hash_2 overflow-pair mismatch"
        );
        assertEq(
            yul.hash_3(Field.PRIME - 1, Field.PRIME - 2, Field.PRIME - 3),
            0x1e113bd1828722623fcea9bc2dacf550b1e60a5db1b4807c3714baa8bd09cb8e,
            "hash_3 stress mismatch"
        );
        assertEq(
            yul.hash_3(1, 2, 3),
            0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
            "hash_3(1,2,3) mismatch"
        );
    }

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
