# Mirror Image (Cryptography): Write-up

**Flag:** `nexsec26{YOU_WILL_NEVER_CATCH_ME_HIDING_BETWEEN_ALL_OF_THESE_MIRRORS_D20_I_CAST_MIRROR_IMAGE_ec8d6a60b0fbecf56c98a2f2ed1e43310e143cf1bc31e1594ec4e4b73f2da837}`

Each mirror showed two possible residues of the archmage's secret. One was real and one was an illusion. Looking at a single mirror could not tell us which to use, but combining all the mirrors gave enough structure to recover the secret.

The first attempt used a general constraint solver and stalled. The working approach used CRT to combine the choices, then LLL lattice reduction to find the small secret.

### 1. Understand the two-shadow problem

The challenge chose a 1024-bit secret `s` and gave us 112 mirrors. Each mirror contained a 16-bit prime `m_i` and two shadows `a_i, b_i`, with:

```text
s mod m_i is either a_i or b_i
```

Trying every choice directly would require up to `2^112` combinations.

The service was at `koala.nexsec.my:38427`. Its output used lines beginning with `mirror =` and a final `ward =` tuple holding the encrypted flag.

### 2. Replace each choice with a sign

Because the moduli are odd primes, division by two is well-defined modulo each prime. We wrote:

$$
\mu_i=(a_i+b_i)\,2^{-1}\pmod{m_i},
\qquad
\delta_i=(b_i-a_i)\,2^{-1}\pmod{m_i}.
$$

Then both shadow choices fit one equation:

$$
s\equiv\mu_i+\varepsilon_i\delta_i\pmod{m_i},
\qquad \varepsilon_i\in\{-1,+1\}.
$$

The minus sign selects `a_i`; the plus sign selects `b_i`. This let us represent all the unknown choices together rather than branch on them one at a time.

### 3. Combine the mirrors with CRT

Let `M` be the product of the moduli. For each mirror, we constructed a CRT weight:

$$
M_i=\frac{M}{m_i},\qquad
E_i=\left(M_i\,(M_i^{-1}\bmod m_i)\right)\bmod M.
$$

Here the inverse is taken modulo `m_i`, and the resulting weight is reduced modulo `M`. Each weight is one modulo its own prime and zero modulo the others.

Using those weights:

$$
U=\sum_i\mu_iE_i\pmod M,
\qquad
W_i=\delta_iE_i\pmod M.
$$

The complete problem becomes:

$$
s\equiv U+\sum_i\varepsilon_iW_i\pmod M.
$$

The useful imbalance is that `M` is much larger than the allowed secret range `0 <= s < 2^1024`. We can use that small-secret condition to guide lattice reduction.

### 4. Build a lattice around the small secret

We centered the secret range with `H = 2^1023` and used scale `K = 2^1023`.

The basis rows were:

- `[M, 0, ..., 0]`
- One row per mirror with `W_i` in the first column and `K` in that mirror's coordinate
- A final row with `(U-H) mod M` in the first column and `K` in the last coordinate

With 112 mirrors, this gives a `114 x 114` basis.

For the correct signs, an integer combination of these rows gives:

$$
(s-H,\varepsilon_1K,\ldots,\varepsilon_{112}K,K).
$$

The first coordinate is small because of the secret's bound. LLL can expose a short vector of this form. It is a practical recovery method here, rather than a guarantee that every instance's shortest vector will appear as a reduced basis row.

### 5. Recover and verify the candidate

The following is the working method from the successful solve, arranged as one notebook cell. It uses Python's socket library, FLINT for LLL, and AES-GCM for decryption.

Install the dependencies in a notebook cell:

```python
%pip install -q python-flint cryptography
```

Then run:

```python
import ast
import socket
from hashlib import sha256

from flint import fmpz_mat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = 'koala.nexsec.my'
PORT = 38427

# Capture one complete instance. Keep its mirrors and ward together.
lines = []
with socket.create_connection((HOST, PORT), timeout=15) as sock:
    with sock.makefile('r', encoding='utf-8') as stream:
        for line in stream:
            lines.append(line)
            if line.strip().startswith('ward ='):
                break

mirrors = []
ward = None
for line in lines:
    line = line.strip()
    if line.startswith('mirror ='):
        mirrors.append(ast.literal_eval(line.split('=', 1)[1].strip()))
    elif line.startswith('ward ='):
        ward = ast.literal_eval(line.split('=', 1)[1].strip())

assert len(mirrors) == 112 and ward is not None

M = 1
for m, shadows in mirrors:
    assert len(shadows) == 2
    M *= m

U = 0
W = []
for m, (a, b) in mirrors:
    inv2 = (m + 1) // 2
    mu = ((a + b) * inv2) % m
    delta = ((b - a) * inv2) % m

    Mi = M // m
    Ei = (Mi * pow(Mi, -1, m)) % M
    U = (U + mu * Ei) % M
    W.append((delta * Ei) % M)

n = len(mirrors)
H = K = 1 << 1023
basis = [[M] + [0] * (n + 1)]

for i in range(n):
    row = [W[i]] + [0] * (n + 1)
    row[i + 1] = K
    basis.append(row)

basis.append([(U - H) % M] + [0] * n + [K])

reduced = fmpz_mat(basis).lll().tolist()
found = False

for row in reduced:
    last = int(row[-1])
    if abs(last) != K:
        continue

    sign = 1 if last == K else -1
    candidate = sign * int(row[0]) + H
    if not 0 <= candidate < (1 << 1024):
        continue
    if not all(candidate % m in shadows for m, shadows in mirrors):
        continue

    key = sha256(candidate.to_bytes(128, 'big')).digest()
    nonce = bytes.fromhex(ward[0])
    ciphertext_and_tag = bytes.fromhex(ward[1])
    flag = AESGCM(key).decrypt(nonce, ciphertext_and_tag, None)
    print(flag.decode('utf-8'))
    found = True
    break

if not found:
    raise RuntimeError('No verified candidate found in the reduced basis')
```

Rows ending in `-K` are normalized by negating the vector. We then shift the first coordinate back by `H` to recover a candidate for `s`.

Before decrypting, the code checks the size bound and confirms that the candidate matches one of the two shadows in **every** mirror. It does not accept a vector merely because it looks short.

The code above is a cleaned-up presentation of the supplied solver. The successful output below is from the supplied run, rather than a new execution during write-up preparation.

### 6. Open the ward

The key is SHA-256 of the secret encoded as exactly 128 big-endian bytes. The fixed width matters: omitting leading zero bytes would change the key.

The ward's first hex field is the nonce. Its second is the ciphertext together with the GCM authentication tag. Decryption uses no additional authenticated data.

The recorded successful attempt was:

```text
--- Attempt 1 ---
[+] Connecting to koala.nexsec.my:38427...
[+] Parsed 112 mirrors. Building CRT lattice...
[+] Running LLL reduction...

[SUCCESS] FLAG -> nexsec26{YOU_WILL_NEVER_CATCH_ME_HIDING_BETWEEN_ALL_OF_THESE_MIRRORS_D20_I_CAST_MIRROR_IMAGE_ec8d6a60b0fbecf56c98a2f2ed1e43310e143cf1bc31e1594ec4e4b73f2da837}
```

The successful solve recovered the secret without guessing the 112 shadow choices individually.
