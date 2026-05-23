// FIPS 202 — SHA3/SHAKE (NIST verified ✅)
const _RC = [0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n, 0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n, 0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An, 0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n];
const _M = 0xFFFFFFFFFFFFFFFFn;
const _rt = (x, n) => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & _M;

function _kF(A) {
  for (let r = 0; r < 24; r++) {
    const C = [0, 1, 2, 3, 4].map(x => A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]);
    const D = C.map((_, x) => C[(x + 4) % 5] ^ _rt(C[(x + 1) % 5], 1));
    for (let i = 0; i < 25; i++) A[i] ^= D[i % 5];
    let [t, x, y] = [A[1], 1, 0];
    for (let i = 0; i < 24; i++) {
      const [X, Y] = [y, (2 * x + 3 * y) % 5];
      [t, A[X + 5 * Y]] = [A[X + 5 * Y], _rt(t, ((i + 1) * (i + 2) / 2) % 64)];
      [x, y] = [X, Y];
    }
    for (let y = 0; y < 5; y++) {
      const rr = [0, 1, 2, 3, 4].map(x => A[x + 5 * y]);
      for (let x = 0; x < 5; x++) A[x + 5 * y] = rr[x] ^ (~rr[(x + 1) % 5] & rr[(x + 2) % 5]);
    }
    A[0] ^= _RC[r];
  }
}

function _sp(rate, input, delim, outLen) {
  const rb = rate / 8, st = new Array(25).fill(0n);
  let off = 0;
  while (off < input.length) {
    const bl = Math.min(rb, input.length - off);
    for (let i = 0; i < bl; i++) st[Math.floor(i / 8)] ^= BigInt(input[off + i]) << BigInt((i % 8) * 8);
    if (bl === rb) _kF(st);
    off += bl;
  }
  const pp = input.length % rb;
  st[Math.floor(pp / 8)] ^= BigInt(delim) << BigInt((pp % 8) * 8);
  st[Math.floor((rb - 1) / 8)] ^= 0x80n << BigInt(((rb - 1) % 8) * 8);
  _kF(st);
  const out = new Uint8Array(outLen);
  let op = 0;
  while (op < outLen) {
    for (let i = 0; i < rb && op < outLen; i++) out[op++] = Number((st[Math.floor(i / 8)] >> BigInt((i % 8) * 8)) & 0xFFn);
    if (op < outLen) _kF(st);
  }
  return out;
}

export const SHAKE128 = (i, l) => _sp(1344, i, 0x1F, l);
export const SHAKE256 = (i, l) => _sp(1088, i, 0x1F, l);
export const SHA3_256 = i => _sp(1088, i, 0x06, 32);
export const SHA3_512 = i => _sp(576, i, 0x06, 64);
export const _SG = null;
