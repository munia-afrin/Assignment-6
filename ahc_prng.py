from dataclasses import dataclass
import hashlib
import struct
import os
from typing import Optional

MASK64 = (1 << 64) - 1

def rotl(x: int, k: int) -> int:
    return ((x << k) & MASK64) | (x >> (64 - k))

def splitmix64(seed: int) -> int:
    z = (seed + 0x9E3779B97F4A7C15) & MASK64
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & MASK64
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB & MASK64
    return z ^ (z >> 31)

@dataclass
class AHC_PRNG:
    seed: Optional[int] = None

    def __post_init__(self):
        if self.seed is None:
            self.seed = int.from_bytes(os.urandom(8), "little")
        sm = splitmix64(self.seed)
        self.s0 = splitmix64(sm + 1)
        self.s1 = splitmix64(sm + 2)
        self.s2 = splitmix64(sm + 3)
        self.s3 = splitmix64(sm + 4)
        self.counter = 1

    def _core_xorshift(self) -> int:
        s0, s1, s2, s3 = self.s0, self.s1, self.s2, self.s3
        t = (s1 << 17) & MASK64
        s2 ^= s0; s3 ^= s1; s1 ^= s2; s0 ^= s3; s2 ^= t
        s3 = rotl(s3, 45)
        self.s0, self.s1, self.s2, self.s3 = s0 & MASK64, s1 & MASK64, s2 & MASK64, s3 & MASK64
        return ((s0 + s3) & MASK64)

    def next_uint64(self) -> int:
        raw = self._core_xorshift()
        data = struct.pack("<QQQQQ", raw, self.s0, self.s1, self.s2, self.counter)
        digest = hashlib.sha256(data).digest()
        out = int.from_bytes(digest[:8], "little") & MASK64
        self.s0 ^= out
        self.counter = (self.counter + 0x517cc1b727220a95) & MASK64
        return out

    def random(self) -> float:
        u64 = self.next_uint64()
        top53 = u64 >> (64 - 53)
        return top53 / float(1 << 53)

    def randint(self, a: int, b: int) -> int:
        if a > b:
            raise ValueError("a must be <= b")
        span = b - a + 1
        while True:
            r = self.next_uint64()
            limit = ((1 << 64) // span) * span
            if r < limit:
                return a + (r % span)

    def randbytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            v = self.next_uint64()
            out.extend(v.to_bytes(8, "little"))
        return bytes(out[:n])

def _basic_tests():
    print("AHC-PRNG self-test / demo")
    prng = AHC_PRNG(seed=0xDEADBEEFCAFEBABE)
    print("Seed:", hex(prng.seed))
    samples = [prng.next_uint64() for _ in range(10)]
    print("10 samples:", samples)
    prng.reseed(123456789)
    print("5 random floats:", [prng.random() for _ in range(5)])
    print("Random bytes:", prng.randbytes(16).hex())

if __name__ == '__main__':
    _basic_tests()

