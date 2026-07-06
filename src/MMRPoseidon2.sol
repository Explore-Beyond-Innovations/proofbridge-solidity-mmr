// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @notice Merkle Mountain Range with Poseidon2 hashing.
 * @dev Indexing starts at 1 (not 0)
 */
library MMRPoseidon2 {
    struct Tree {
        bytes32 root; // Poseidon2 root commitment
        uint256 size; // total number of nodes in the implicit forest
        uint256 width; // number of leaves appended so far
        address hasher; // deployed Poseidon2Yul, set once via setHasher
        mapping(uint256 => bytes32) hashes; // nodeIndex => nodeHash
    }

    // keccak256("ProofBridge.MMR.v1") mod p - domain/version tag bound into the root; must match the circuit + SDK.
    bytes32 internal constant DOMAIN_TAG = 0x1007fd40caf0e39d3ffbecd91e2d9469b3f2294a6794c372eb5406a496b6e4ec;

    // BN254 scalar field modulus; all hash inputs are reduced into it.
    uint256 internal constant PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // ========= internal / EXTERNAL-FACING LOGIC =========

    /**
     * @notice Wire up the Poseidon2 hasher. Must be called once before any append/verify.
     * @dev `hasher_` is a deployed Poseidon2Yul; hashing is done via staticcall for the gas win.
     */
    function setHasher(Tree storage tree, address hasher_) internal {
        require(hasher_ != address(0), "MMR:ZeroHasher");
        tree.hasher = hasher_;
    }

    /**
     * @notice Append a new leaf.
     * @dev dataHash is any bytes32 you consider "leaf payload hash".
     *      We mod it into the Poseidon field to keep consistency.
     *
     * Effects:
     *  - updates width, size, root
     *  - writes new leaf hash and any internal branch hashes
     */
    function append(Tree storage tree, bytes32 dataHash) internal returns (uint256 newLeafIndex) {
        // fit into Poseidon2 field
        bytes32 dataHashMod = _fieldMod(dataHash);

        // increment logical width (#leaves)
        tree.width += 1;

        // compute the leaf index for this new leaf in the "mountain range index space"
        newLeafIndex = getLeafIndex(tree.width);

        // hash leaf node as Poseidon2(index || value)
        bytes32 leafNode = _hashLeaf(tree.hasher, newLeafIndex, dataHashMod);

        // store leaf in node map
        tree.hashes[newLeafIndex] = leafNode;

        // figure out peak indexes (the tops of each "mountain")
        uint256[] memory peakIndexes = _getPeakIndexes(tree.width);

        // update size to rightmost peak index
        tree.size = _calcSize(tree.width);

        // walk each peak top → recursively fill internal hashes if missing
        bytes32[] memory peaks = new bytes32[](peakIndexes.length);
        for (uint256 i = 0; i < peakIndexes.length; i++) {
            peaks[i] = _getOrCreateNode(tree, peakIndexes[i]);
        }

        // recompute MMR root as "peak bagging" of all current peaks
        tree.root = _peakBagging(tree.hasher, tree.width, peaks);
    }

    /**
     * @notice Return current root.
     */
    function getRoot(Tree storage tree) internal view returns (bytes32) {
        return tree.root;
    }

    /**
     * @notice Return current width (#leaves).
     */
    function getWidth(Tree storage tree) internal view returns (uint256) {
        return tree.width;
    }

    /**
     * @notice Return current size (MMR node space upper bound).
     */
    function getSize(Tree storage tree) internal view returns (uint256) {
        return tree.size;
    }

    /**
     * @notice Get stored node hash at an absolute node index (1-based).
     */
    function getNodeHash(Tree storage tree, uint256 index) internal view returns (bytes32) {
        return tree.hashes[index];
    }

    /**
     * @notice Return all peak hashes (same order as in peak bagging).
     */
    function getPeaks(Tree storage tree) internal view returns (bytes32[] memory peaks) {
        uint256[] memory peakNodeIndexes = _getPeakIndexes(tree.width);
        peaks = new bytes32[](peakNodeIndexes.length);
        for (uint256 i = 0; i < peakNodeIndexes.length; i++) {
            peaks[i] = tree.hashes[peakNodeIndexes[i]];
        }
    }

    /**
     * @notice Compute the leaf index for the given width.
     * @dev Width is 1-indexed count of leaves; leaf index is 1-indexed MMR node index.
     */
    function getLeafIndex(uint256 width_) internal pure returns (uint256) {
        // same 1-indexed indexing logic
        if (width_ % 2 == 1) {
            return _calcSize(width_);
        } else {
            return _calcSize(width_ - 1) + 1;
        }
    }

    /**
     * @notice Build Merkle inclusion proof for a specific leaf index.
     * @dev Reverts if index is not a leaf or out of range.
     *
     * Returns:
     *  - root: current root
     *  - width: current width (#leaves)
     *  - peakBag: array of peak hashes used in peak bagging
     *  - siblings: sibling path from leaf → peak
     */
    function getMerkleProof(Tree storage tree, uint256 index)
        internal
        view
        returns (bytes32 root_, uint256 width_, bytes32[] memory peakBag, bytes32[] memory siblings)
    {
        require(index <= tree.size, "MMR:OutOfRange");
        require(_isLeaf(index), "MMR:NotLeaf");

        root_ = tree.root;
        width_ = tree.width;

        // gather peaks + locate which peak covers this index
        uint256[] memory peakIdxs = _getPeakIndexes(tree.width);
        peakBag = new bytes32[](peakIdxs.length);

        uint256 cursor = 0;
        for (uint256 i = 0; i < peakIdxs.length; i++) {
            peakBag[i] = tree.hashes[peakIdxs[i]];
            if (peakIdxs[i] >= index && cursor == 0) {
                cursor = peakIdxs[i];
            }
        }
        require(cursor != 0, "MMR:PeakNotFound");

        // descend from that peak down to the index, recording siblings
        uint8 h = _heightAt(cursor);
        siblings = new bytes32[](h - 1);

        while (cursor != index) {
            h--;
            (uint256 left, uint256 right) = _getChildren(cursor);
            // go down
            cursor = index <= left ? left : right;
            // record sibling
            siblings[h - 1] = tree.hashes[index <= left ? right : left];
        }
    }

    /**
     * @notice Check proof on-chain (stateless verifier).
     * @dev Matches inclusionProof logic in your previous version.
     */
    function verifyInclusion(
        address hasher,
        bytes32 root_,
        uint256 width_,
        uint256 index,
        bytes32 valueHash,
        bytes32[] memory peakBag,
        bytes32[] memory siblings
    ) internal view returns (bool) {
        require(_calcSize(width_) >= index, "MMR:IndexOOB");

        // root must equal bagged peak hash
        require(root_ == _peakBagging(hasher, width_, peakBag), "MMR:BadRoot");

        // find target peak + starting cursor
        bytes32 targetPeak;
        uint256 cursor;
        {
            uint256[] memory peakIdxs = _getPeakIndexes(width_);
            for (uint256 i = 0; i < peakIdxs.length; i++) {
                if (peakIdxs[i] >= index) {
                    targetPeak = peakBag[i];
                    cursor = peakIdxs[i];
                    break;
                }
            }
        }
        require(targetPeak != bytes32(0), "MMR:NoPeakForIndex");

        // walk DOWN from peak to the index, record path
        uint256[] memory path = new uint256[](siblings.length + 1);
        uint8 h = uint8(siblings.length) + 1;
        while (h > 0) {
            path[--h] = cursor;
            if (cursor == index) break;
            (uint256 l, uint256 r) = _getChildren(cursor);
            cursor = index > l ? r : l;
        }

        // now walk UP recomputing hashes
        bytes32 node;
        while (h < path.length) {
            cursor = path[h];
            if (h == 0) {
                // leaf
                node = _hashLeaf(hasher, cursor, valueHash);
            } else if (cursor - 1 == path[h - 1]) {
                // sibling is on the left
                node = _hashBranch(hasher, cursor, siblings[h - 1], node);
            } else {
                // sibling is on the right
                node = _hashBranch(hasher, cursor, node, siblings[h - 1]);
            }
            h++;
        }

        require(node == targetPeak, "MMR:BadPeakHash");
        return true;
    }

    // ========= INTERNAL / PURE HELPERS =========

    function _calcSize(uint256 width_) internal pure returns (uint256) {
        // (width << 1) - popcount(width)
        return (width_ << 1) - _numOfPeaks(width_);
    }

    // Poseidon2 via staticcall to the deployed Yul hasher (poseidon2-evm >= v2: selector-prefixed
    // IPoseidon2 calling convention). Inputs reduced into the field first.
    function _hash2(address hasher, uint256 a, uint256 b) private view returns (bytes32) {
        (bool ok, bytes memory ret) =
            hasher.staticcall(abi.encodeWithSignature("hash_2(uint256,uint256)", a % PRIME, b % PRIME));
        require(ok, "MMR:HashFail");
        return abi.decode(ret, (bytes32));
    }

    function _hash3(address hasher, uint256 a, uint256 b, uint256 c) private view returns (bytes32) {
        (bool ok, bytes memory ret) = hasher.staticcall(
            abi.encodeWithSignature(
                "hash_3(uint256,uint256,uint256)", a % PRIME, b % PRIME, c % PRIME
            )
        );
        require(ok, "MMR:HashFail");
        return abi.decode(ret, (bytes32));
    }

    function _hashBranch(address hasher, uint256 index, bytes32 left, bytes32 right) internal view returns (bytes32) {
        return _hash3(hasher, index, uint256(left), uint256(right));
    }

    function _hashLeaf(address hasher, uint256 index, bytes32 dataHash) internal view returns (bytes32) {
        return _hash2(hasher, index, uint256(dataHash));
    }

    function _fieldMod(bytes32 dataHash) internal pure returns (bytes32) {
        // reduce into BN256 scalar field to align with Poseidon2 field
        return bytes32(uint256(dataHash) % PRIME);
    }

    function _peakBagging(address hasher, uint256 width_, bytes32[] memory peaks_) internal view returns (bytes32) {
        if (width_ == 0) return bytes32(0);

        uint256 size_ = _calcSize(width_);
        require(_numOfPeaks(width_) == peaks_.length, "MMR:BadPeakCount");

        // single size-bind: fold the peaks seeded by the first peak (not size)
        bytes32 acc = peaks_[0];
        for (uint256 i = 1; i < peaks_.length; i++) {
            acc = _hash2(hasher, uint256(acc), uint256(peaks_[i]));
        }

        // bind size + domain once: root = H_3(DOMAIN_TAG, size, acc)
        return _hash3(hasher, uint256(DOMAIN_TAG), size_, uint256(acc));
    }

    function _getPeakIndexes(uint256 width_) internal pure returns (uint256[] memory peakIndexes) {
        uint256 numPeaks = _numOfPeaks(width_);
        peakIndexes = new uint256[](numPeaks);

        // compute maxHeight (same as your version)
        uint8 maxHeight = 1;
        while ((1 << maxHeight) <= width_) {
            maxHeight++;
        }

        uint256 count;
        uint256 runningSize;
        for (uint256 i = maxHeight; i > 0; i--) {
            if (width_ & (1 << (i - 1)) != 0) {
                runningSize = runningSize + (1 << i) - 1;
                peakIndexes[count++] = runningSize;
            }
        }

        require(count == numPeaks, "MMR:PeakCalcMismatch");
    }

    function _heightAt(uint256 index) internal pure returns (uint8 height) {
        uint256 reducedIndex = index;
        uint256 peakIndex;
        while (reducedIndex > peakIndex) {
            reducedIndex -= (uint256(1) << height) - 1;
            height = _mountainHeight(reducedIndex);
            peakIndex = (uint256(1) << height) - 1;
        }
        height = height - uint8((peakIndex - reducedIndex));
    }

    function _isLeaf(uint256 index) internal pure returns (bool) {
        return _heightAt(index) == 1;
    }

    function _getChildren(uint256 index) internal pure returns (uint256 left, uint256 right) {
        left = index - (uint256(1) << (_heightAt(index) - 1));
        right = index - 1;
        require(left != right, "MMR:NotParent");
    }

    function _mountainHeight(uint256 size_) internal pure returns (uint8) {
        uint8 height = 1;
        while (uint256(1) << height <= size_ + height) {
            height++;
        }
        return height - 1;
    }

    function _numOfPeaks(uint256 width_) internal pure returns (uint256 num) {
        uint256 bits = width_;
        while (bits > 0) {
            num++;
            bits = bits & (bits - 1); // pop low set bit
        }
    }

    // NOTE: _getOrCreateNode is the only mutating helper left outside append()
    function _getOrCreateNode(Tree storage tree, uint256 index) private returns (bytes32) {
        require(index <= tree.size, "MMR:OOBNode");
        bytes32 cached = tree.hashes[index];
        if (cached != bytes32(0)) return cached;

        (uint256 leftIdx, uint256 rightIdx) = _getChildren(index);
        bytes32 leftHash = _getOrCreateNode(tree, leftIdx);
        bytes32 rightHash = _getOrCreateNode(tree, rightIdx);

        bytes32 branch = _hashBranch(tree.hasher, index, leftHash, rightHash);
        tree.hashes[index] = branch;
        return branch;
    }
}
