"""Logistic 混沌映射：x_{n+1} = mu * x_n * (1 - x_n)

用途：
  1. 生成伪随机比特序列，对水印比特流做混淆（XOR）
  2. 生成伪随机置换，打乱比特位置（置换）
  3. 生成嵌入点位置序列

密钥 = (x0, mu)。x0 ∈ (0,1)，mu ∈ (3.57, 4.0)（混沌区）。
密钥保密：没有密钥即使提取出零宽字符序列也无法还原水印 ID。
"""
import hashlib
import math
from typing import Iterator

MU_MIN = 3.57
MU_MAX = 4.0


def random_key() -> tuple[float, float]:
    """随机生成一组混沌密钥（用于新水印文件）。"""
    import secrets
    x0 = 0.05 + (secrets.randbelow(900000) / 1000000.0) * 0.9   # 0.05 ~ 0.95
    mu = MU_MIN + (secrets.randbelow(430000) / 1000000.0)        # 3.57 ~ 4.00
    return (round(x0, 12), round(mu, 12))


def _validate(x0: float, mu: float) -> None:
    if not (0.0 < x0 < 1.0):
        raise ValueError("x0 必须在 (0,1) 区间")
    if not (MU_MIN <= mu <= MU_MAX):
        raise ValueError("mu 必须在 [3.57, 4.0] 区间")


def iterate(x0: float, mu: float, skip: int = 128) -> Iterator[float]:
    """迭代生成混沌序列，丢弃前 skip 个瞬态点。"""
    _validate(x0, mu)
    x = x0
    for _ in range(skip):
        x = mu * x * (1.0 - x)
        if x <= 0.0 or x >= 1.0:          # 数值逃逸保护
            x = 0.5
    while True:
        x = mu * x * (1.0 - x)
        if x <= 0.0 or x >= 1.0:
            x = (x % 1.0) or 0.5
        yield x


def bit_stream(x0: float, mu: float, length: int, channel: int = 0) -> list[int]:
    """由混沌序列量化出比特流（取小数二进制的第 channel 位，避免单调性偏差）。"""
    gen = iterate(x0, mu, skip=128 + channel * 977)
    bits = []
    for _ in range(length):
        x = next(gen)
        # 取小数部分放大后的某一位，抗单调相关
        q = int(x * (1 << 32)) & 0xFFFFFFFF
        bits.append((q >> (16 + (channel % 8))) & 1)
    return bits


def keystream_bytes(x0: float, mu: float, length: int, salt: str = "") -> bytes:
    """生成字节流密钥（用于 XOR / 置换）。"""
    out = bytearray()
    seed = f"{x0:.15f}|{mu:.15f}|{salt}".encode()
    block = hashlib.sha256(seed).digest()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(block + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def xor_bits(bits: list[int], x0: float, mu: float, salt: str = "") -> list[int]:
    ks = keystream_bytes(x0, mu, (len(bits) + 7) // 8, salt=salt or "xor")
    kbits = [(b >> i) & 1 for b in ks for i in range(7, -1, -1)]
    return [b ^ k for b, k in zip(bits, kbits)]


def permutation(n: int, x0: float, mu: float, salt: str = "") -> list[int]:
    """基于混沌密钥生成 0..n-1 的伪随机置换。"""
    order = list(range(n))
    # 用混沌实数排序，天然得到一个置换，且可复现
    gen = iterate(x0, mu, skip=512)
    keys = []
    for _ in range(n):
        x = next(gen)
        h = hashlib.sha256(f"{salt}|{x:.17f}".encode()).digest()
        keys.append(int.from_bytes(h[:8], "big"))
    return [i for _, i in sorted(zip(keys, order), key=lambda t: t[0])]


def block_sequence(n: int, need: int, x0: float, mu: float,
                   salt: str = "") -> list[int]:
    """确定性的伪随机块序列（模步进），复杂度 O(need) 而不是 O(n)。

    permutation() 需要对 n 个块逐个哈希再排序；一张 1650×2200 的图有 5.6 万个块，
    每张图每个候选密钥都要重算一次，一本多插图的书会直接卡住。
    这里改成「起点 + 步长」的模遍历：步长与 n 互质 ⇒ 前 need 项必然互不重复，
    且两端（嵌入 / 提取）用同一密钥得到同一序列的前缀，天然对齐。
    """
    if n <= 0 or need <= 0:
        return []
    need = min(need, n)
    ks = keystream_bytes(x0, mu, 32, salt=salt or "seq")
    start = int.from_bytes(ks[0:8], "big") % n
    stride = int.from_bytes(ks[8:16], "big") % n
    if stride <= 0:
        stride = 1
    guard = 0
    while math.gcd(stride, n) != 1 and guard < 64:
        stride = (stride + 1) % n or 1
        guard += 1
    return [(start + i * stride) % n for i in range(need)]


def permute(bits: list[int], x0: float, mu: float, salt: str = "") -> list[int]:
    """按密钥置换比特位置。"""
    perm = permutation(len(bits), x0, mu, salt=salt or "perm")
    return [bits[p] for p in perm]


def unpermute(bits: list[int], x0: float, mu: float, salt: str = "") -> list[int]:
    """permute 的逆操作。"""
    perm = permutation(len(bits), x0, mu, salt=salt or "perm")
    out = [0] * len(bits)
    for src, dst in enumerate(perm):
        out[dst] = bits[src]
    return out
