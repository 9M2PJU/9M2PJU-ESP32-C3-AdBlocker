#!/usr/bin/env python3
"""Tests for build_blocklist.py — verifies hashing, normalization, binary format,
and Bloom filter correctness. Run: python3 tools/test_build_blocklist.py"""
import sys, os, struct, tempfile, math

sys.path.insert(0, os.path.dirname(__file__))
from build_blocklist import (
    fnv64, fnv40, norm, optimal_k, bloom_positions,
    HASH_BYTES, MASK, FNV_OFFSET, FNV_PRIME, MAGIC, VERSION, HEADER_SIZE
)

PASS = 0
FAIL = 0

def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  PASS: {name}')
    else:
        FAIL += 1
        print(f'  FAIL: {name}')

# ---- FNV-1a known vectors ----
# FNV-1a 64-bit: offset basis = 0xcbf29ce484222325, prime = 0x100000001b3
# Empty string -> offset basis
check('fnv64 empty = offset basis', fnv64(b'') == FNV_OFFSET)
# "a" = (offset ^ 'a') * prime
expected_a = ((FNV_OFFSET ^ ord('a')) * FNV_PRIME) & ((1 << 64) - 1)
check('fnv64("a") matches manual', fnv64(b'a') == expected_a)
# "foobar" known FNV-1a 64-bit = 0x85944171f73967e8
check('fnv64("foobar") = known vector', fnv64(b'foobar') == 0x85944171f73967e8)

# ---- 40-bit truncation ----
h64 = fnv64(b'doubleclick.net')
check('fnv40 = fnv64 & MASK', fnv40(b'doubleclick.net') == (h64 & MASK))
check('fnv40 < 2^40', fnv40(b'doubleclick.net') < (1 << 40))

# ---- normalization ----
check('norm strips www.', norm('www.ads.com') == 'ads.com')
check('norm lowercases', norm('ADS.Com') == 'ads.com')
check('norm strips leading dot', norm('.evil.com') == 'evil.com')
check('norm strips trailing dot', norm('evil.com.') == 'evil.com')
check('norm strips leading *.', norm('*.wildcard.com') == 'wildcard.com')
check('norm keeps bare domain', norm('example.net') == 'example.net')
check('norm keeps multi-level', norm('a.b.c.d') == 'a.b.c.d')

# ---- optimal_k ----
check('optimal_k(0, ...) = 0', optimal_k(0, 1024) == 0)
check('optimal_k(n, 0) = 0', optimal_k(100, 0) == 0)
check('optimal_k >= 1 for valid input', optimal_k(100, 10000) >= 1)
# For 140k domains, 2^20 bits: k ~ 5
k140k = optimal_k(140000, 1 << 20)
check('optimal_k(140k, 2^20) ~ 5', 4 <= k140k <= 6)

# ---- Bloom filter correctness ----
bloom_bits = 1024
k = 4
# Insert a domain and verify it's found
h = fnv64(b'test.example.com')
positions = list(bloom_positions(h, bloom_bits, k))
check('bloom_positions returns k positions', len(positions) == k)
check('bloom_positions in range', all(0 <= p < bloom_bits for p in positions))
# Simulate bloom insert + lookup
bloom = bytearray((bloom_bits + 7) // 8)
for pos in positions:
    bloom[pos >> 3] |= (1 << (pos & 7))
# Verify lookup
h_check = fnv64(b'test.example.com')
found = all(bloom[p >> 3] & (1 << (p & 7)) for p in bloom_positions(h_check, bloom_bits, k))
check('bloom contains inserted item', found)
# Verify a different item is likely not found (not a guarantee, but with small k and large m it's likely)
h_other = fnv64(b'definitely.not.inserted.xyz')
found_other = all(bloom[p >> 3] & (1 << (p & 7)) for p in bloom_positions(h_other, bloom_bits, k))
check('bloom likely rejects uninserted item', not found_other)

# ---- Binary format test ----
print('\nBinary format tests:')
with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tf:
    test_bin = tf.name

# Create a small test hosts file
with tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False) as tf:
    tf.write('0.0.0.0 ads.example.com\n')
    tf.write('0.0.0.0 www.tracker.evil.net\n')
    tf.write('127.0.0.1 malware.bad.dns.com\n')
    tf.write('clean.domain.com\n')
    tf.write('# comment line\n')
    tf.write('\n')
    test_hosts = tf.name

# Build blocklist
import subprocess
r = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), 'build_blocklist.py'),
                    test_bin, test_hosts, '--bloom-bits', '512'],
                   capture_output=True, text=True)
check('build script exits 0', r.returncode == 0)

# Read and validate the binary
with open(test_bin, 'rb') as f:
    data = f.read()

check('file >= header size', len(data) >= HEADER_SIZE)
check('magic = CADB', data[0:4] == MAGIC)
check('version = 1', data[4] == VERSION)
check('hash_bytes = 5', data[5] == HASH_BYTES)

num_hashes = struct.unpack('<I', data[6:10])[0]
bloom_bits_read = struct.unpack('<I', data[10:14])[0]
bloom_k_read = data[14]

# Expected domains: ads.example.com, tracker.evil.net, malware.bad.dns.com, clean.domain.com
# (www. stripped from tracker.evil.net)
check('num_hashes = 4', num_hashes == 4)
check('bloom_bits = 512', bloom_bits_read == 512)
check('bloom_k > 0', bloom_k_read > 0)

# Validate bloom filter size
bloom_bytes = (bloom_bits_read + 7) // 8
expected_size = HEADER_SIZE + bloom_bytes + num_hashes * HASH_BYTES
check('file size matches header', len(data) == expected_size)

# Read hash table and verify it's sorted
hash_offset = HEADER_SIZE + bloom_bytes
hashes = []
for i in range(num_hashes):
    h_bytes = data[hash_offset + i * HASH_BYTES : hash_offset + (i + 1) * HASH_BYTES]
    h = int.from_bytes(h_bytes, 'little')
    hashes.append(h)
check('hashes are sorted', hashes == sorted(hashes))
check('all hashes < 2^40', all(h < (1 << 40) for h in hashes))

# Verify a known domain is in the hash table
expected_hash = fnv40(b'ads.example.com')
check('ads.example.com hash in table', expected_hash in hashes)

# Verify a non-blocked domain is NOT in the hash table
not_blocked = fnv40(b'google.com')
check('google.com hash NOT in table', not_blocked not in hashes)

# ---- Cleanup ----
os.unlink(test_bin)
os.unlink(test_hosts)
collisions_file = test_bin + '.collisions.txt'
if os.path.exists(collisions_file):
    os.unlink(collisions_file)

print(f'\n{"=" * 40}')
print(f'Results: {PASS} passed, {FAIL} failed')
sys.exit(1 if FAIL else 0)
