# secp256k1 implementada a mano (punto en forma afín, double-and-add)
# Solo derivación de clave pública desde clave privada.

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = (Gx, Gy)

def inverse_mod(k: int, p: int = P) -> int:
    if k % p == 0:
        raise ZeroDivisionError("inverse_mod of zero")
    return pow(k, p - 2, p)

def is_on_curve(Pt):
    if Pt is None:
        return True
    x, y = Pt
    return (y * y - (x * x * x + A * x + B)) % P == 0

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and y1 != y2:
        return None
    if P1 == P2:
        # tangent slope
        m = (3 * x1 * x1 + A) * inverse_mod(2 * y1, P) % P
    else:
        m = (y2 - y1) * inverse_mod((x2 - x1) % P, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k: int, point=G):
    if k % N == 0 or point is None:
        return None
    k = k % N
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    if not is_on_curve(result):
        raise ValueError("Resultado fuera de la curva")
    return result

def privkey_to_pubkey_uncompressed(privkey_bytes: bytes) -> bytes:
    k = int.from_bytes(privkey_bytes, "big")
    if not (1 <= k < N):
        raise ValueError("Clave privada fuera de rango")
    x, y = scalar_mult(k, G)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

def privkey_to_pubkey_compressed(privkey_bytes: bytes) -> bytes:
    k = int.from_bytes(privkey_bytes, "big")
    if not (1 <= k < N):
        raise ValueError("Clave privada fuera de rango")
    x, y = scalar_mult(k, G)
    prefix = b"\x02" if (y % 2 == 0) else b"\x03"
    return prefix + x.to_bytes(32, "big")
