#!/usr/bin/env python3
"""merkle_tree2 — Merkle tree with proof generation and verification. Zero deps."""
import hashlib

def _hash(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()

class MerkleTree:
    def __init__(self, data):
        self.leaves = [_hash(d) for d in data]
        self.tree = self._build(self.leaves[:])

    def _build(self, leaves):
        if not leaves: return [[_hash("")]]
        if len(leaves) % 2: leaves.append(leaves[-1])
        tree = [leaves]
        while len(leaves) > 1:
            level = []
            for i in range(0, len(leaves), 2):
                level.append(_hash(leaves[i] + leaves[i+1]))
            if len(level) > 1 and len(level) % 2:
                level.append(level[-1])
            tree.append(level)
            leaves = level
        return tree

    @property
    def root(self): return self.tree[-1][0]

    def proof(self, index):
        proof = []
        for level in self.tree[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                proof.append(('left' if index % 2 else 'right', level[sibling]))
            index //= 2
        return proof

    @staticmethod
    def verify(leaf_hash, proof, root):
        current = leaf_hash
        for side, sibling in proof:
            if side == 'right':
                current = _hash(current + sibling)
            else:
                current = _hash(sibling + current)
        return current == root

def main():
    data = ["tx1: Alice->Bob $50", "tx2: Bob->Carol $30", "tx3: Carol->Dave $20", "tx4: Dave->Eve $10"]
    mt = MerkleTree(data)
    print(f"Merkle Tree ({len(data)} leaves):")
    print(f"  Root: {mt.root[:16]}...")
    for i, level in enumerate(mt.tree):
        print(f"  Level {i}: {[h[:8] for h in level]}")

    # Proof for tx2
    idx = 1
    proof = mt.proof(idx)
    print(f"\nProof for '{data[idx]}':")
    for side, h in proof:
        print(f"  {side}: {h[:16]}...")
    valid = MerkleTree.verify(mt.leaves[idx], proof, mt.root)
    print(f"  Valid: {valid}")

    # Tampered
    fake_hash = _hash("tx2: Bob->Carol $9999")
    valid2 = MerkleTree.verify(fake_hash, proof, mt.root)
    print(f"  Tampered valid: {valid2}")

if __name__ == "__main__":
    main()
