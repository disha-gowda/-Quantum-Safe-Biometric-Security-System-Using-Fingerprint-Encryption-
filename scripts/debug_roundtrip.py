import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qsbas.cipher import QSBACCipher
from qsbas.keys import build_session_material, permutation_indices
from qsbas.layers import (
    apply_permutation,
    apply_rotation,
    build_dynamic_sbox,
    diffusion_forward,
    diffusion_inverse,
    inverse_permutation,
    inverse_rotation,
    inverse_sbox_substitute,
    sbox_substitute,
)
from qsbas.utils import rotl8, rotr8, bytes_to_int_list

fp = str(ROOT / "data" / "sample_fingerprint.png")
cipher = QSBACCipher.from_image_path(fp)
plain = b"Hello"
data = bytes_to_int_list(plain)
n = len(data)
mat, x0 = cipher._material(n, None)
features, chaotic, keys = mat.features, mat.chaotic, mat.keys
perm = mat.perm_indices

permuted = apply_permutation(data, perm)
rotations = [(features[i] ^ chaotic[i] ^ i) & 7 for i in range(n)]
rotated = apply_rotation(permuted, rotations)
diffused = diffusion_forward(rotated, keys, chaotic)
sbox = build_dynamic_sbox(features, chaotic, x0=x0)
subbed = sbox_substitute(diffused, sbox)

encrypted = []
prev_c = 0
for i in range(n):
    d = subbed[i]
    s_i = (chaotic[i] ^ features[i] ^ i) & 0xFF
    inner = rotl8(((d ^ s_i) + chaotic[i]) & 0xFF, rotations[i])
    e = (inner ^ (perm[i] % n) ^ prev_c) & 0xFF
    encrypted.append(e)
    prev_c = e

# decrypt partial
after_final = []
prev_c = 0
for i in range(n):
    e = encrypted[i]
    inner = (e ^ (perm[i] % n) ^ prev_c) & 0xFF
    inner = rotr8(inner, rotations[i])
    inner = (inner - chaotic[i]) & 0xFF
    d = (inner ^ ((chaotic[i] ^ features[i] ^ i) & 0xFF)) & 0xFF
    after_final.append(d)
    prev_c = encrypted[i]

rec_diffused = inverse_sbox_substitute(after_final, sbox)
rec_rotated = diffusion_inverse(rec_diffused, keys, chaotic)
rec_permuted = inverse_rotation(rec_rotated, rotations)
rec_plain = inverse_permutation(rec_permuted, perm)

print("plain", plain)
print("rec", bytes(rec_plain))
print("subbed ok", after_final == subbed)
print("diffused ok", rec_diffused == diffused)
print("rotated ok", rec_rotated == rotated)
print("permuted ok", rec_permuted == permuted)
print("perm ok", rec_plain == data)
