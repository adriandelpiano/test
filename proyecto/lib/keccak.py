# Keccak-256 puro en Python, correcto para Ethereum (no SHA3-256).
# Test rápido: keccak256(b"") == c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470

RC = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008
]

# Offsets de rotación estándar (matriz 5x5)
RHO = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]

def _rotl64(x, n):
    n &= 63
    return ((x << n) & ((1 << 64) - 1)) | (x >> (64 - n))

def _index(x, y):
    return x + 5 * y

def keccak_f1600(state):
    # state: lista de 25 enteros de 64 bits (5x5)
    for rnd in range(24):
        # Theta
        C = [state[_index(x,0)] ^ state[_index(x,1)] ^ state[_index(x,2)] ^ state[_index(x,3)] ^ state[_index(x,4)] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl64(C[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[_index(x,y)] ^= D[x]
        # Rho y Pi
        B = [0] * 25
        for y in range(5):
            for x in range(5):
                X = y
                Y = (2*x + 3*y) % 5
                B[_index(X,Y)] = _rotl64(state[_index(x,y)], RHO[x][y])
        # Chi
        for y in range(5):
            t0 = B[_index(0,y)]
            t1 = B[_index(1,y)]
            t2 = B[_index(2,y)]
            t3 = B[_index(3,y)]
            t4 = B[_index(4,y)]
            state[_index(0,y)] = t0 ^ ((~t1) & t2)
            state[_index(1,y)] = t1 ^ ((~t2) & t3)
            state[_index(2,y)] = t2 ^ ((~t3) & t4)
            state[_index(3,y)] = t3 ^ ((~t4) & t0)
            state[_index(4,y)] = t4 ^ ((~t0) & t1)
        # Iota
        state[0] ^= RC[rnd]

def keccak256(data: bytes) -> bytes:
    rate = 1088 // 8   # 136 bytes
    outlen = 256 // 8  # 32 bytes
    state = [0] * 25

    # Absorción por bloques completos
    i = 0
    while i + rate <= len(data):
        block = data[i:i+rate]
        # XOR en lanes de 64 bits (little-endian)
        for j in range(0, rate, 8):
            lane = int.from_bytes(block[j:j+8], "little")
            state[j // 8] ^= lane
        keccak_f1600(state)
        i += rate

    # Padding Keccak (pad10*1 con 0x01 ... 0x80)
    rem = data[i:]
    pad = bytearray(rem)
    pad += b"\x01"
    pad += b"\x00" * (rate - len(pad) - 1)
    pad += b"\x80"

    for j in range(0, rate, 8):
        lane = int.from_bytes(pad[j:j+8], "little")
        state[j // 8] ^= lane
    keccak_f1600(state)

    # Squeeze
    out = bytearray()
    while len(out) < outlen:
        for j in range(0, rate, 8):
            out += state[j // 8].to_bytes(8, "little")
            if len(out) >= outlen:
                break
        if len(out) >= outlen:
            break
        keccak_f1600(state)
    return bytes(out[:outlen])

# Test interno opcional (puede comentarse en producción):
if __name__ == "__main__":
    h = keccak256(b"").hex()
    print("[TEST] keccak256(\"\") =", h)
    assert h == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "Keccak-256 incorrecto"
