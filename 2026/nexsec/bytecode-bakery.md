# Bytecode Bakery (RE): Write-up

**Recovered flag:** `nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}`

The bakery's oven ran a small stack-based virtual machine. The recipe was a flag checker, so we needed to understand its instructions and recover the input that passed the checks.

The first readable flag was a decoy. Following the actual entry point led to a different checker and the full 50-byte answer.

### 1. Read the recipe header

The challenge supplied `oven.py` and `recipe.bin`, with these SHA-256 values:

```text
oven.py:
161e6c15bf0305132257d5d9f6f1732dca1976afa383d2023df5573266744782

recipe.bin:
ee84b6f469eb82dac886786e28e65e8ea1a3a3436d2778a0e1a54b4b467db4a0
```

The recipe format starts with an eight-byte header:

| Offset | Meaning |
| --- | --- |
| 0–3 | Magic bytes `BAKE` |
| 4 | Version |
| 5 | Required input length |
| 6–7 | Bytecode length, little-endian |
| 8 onward | Bytecode |

The header can be read with:

```python
import struct

blob = open('recipe.bin', 'rb').read()
assert blob[:4] == b'BAKE'
version, input_len, code_len = struct.unpack('<BBH', blob[4:8])
code = blob[8:8 + code_len]
```

The recorded disassembly reported:

```text
input_len=50, code_len=1143
```

This immediately gave us a useful check: a complete candidate had to be 50 bytes long.

### 2. Follow the jump before decoding the checks

The beginning of the bytecode was:

```text
0000: JMP   0x00ec
0003: PUSH  0x01
...
00e7: JNZ   0x00eb
00ea: FAIL
00eb: OK
00ec: PUSH  0x01
```

The block at `0x0003` used simple independent XOR checks. Decoding those produced:

```text
nexsec26{n0t_th15_r3c1p3}
```

It looked like a flag, but it was only 25 bytes long. More importantly, the first instruction jumped past that block to `0x00ec`. We needed to solve the active checker rather than trust the easier string.

The real result and the decoy share the prefix `nexsec26{`, but diverge at input index 9. Matching the first few characters did not establish that the whole decoy was correct.

### 3. Turn the active instructions into equations

The active checker used loads, XOR, eight-bit rotation, addition or subtraction, and equality tests. Its first block was:

```text
LOAD 0x00
PUSH 0xaa
XOR
PUSH 0x8b
XOR
PUSH 0x07
ROL
PUSH 0xdd
SUB
PUSH 0xca
EQ
AND
```

That corresponds to:

```text
(ROL8(b0 XOR 0xaa XOR 0x8b, 7) - 0xdd) mod 256 = 0xca
```

We reversed the subtraction and rotation, then XORed the constants back out:

```python
def ror8(value, count):
    count &= 7
    return ((value >> count) | (value << (8 - count))) & 0xff

b0 = ror8((0xca + 0xdd) & 0xff, 7) ^ 0xaa ^ 0x8b
# 0x6e, or 'n'
```

Later blocks also XORed the current input byte with the previous byte:

```text
ROL8(b[i] XOR b[i-1] XOR C, r) + A = E  (mod 256)
```

Once the preceding byte was known, the next byte could be recovered directly. No search over the whole flag was needed.

### 4. Fix the parser's look-ahead

The first arithmetic parser expected one XOR constant per block. It failed at `0xf5` because the first block had two constants: `0xaa` and `0x8b`.

The next version tried to consume every `PUSH` as another XOR constant. That failed at `0xf8`, where `PUSH 0x07` was followed by `ROL`.

The fix was to look past the immediate byte and consume a pair only when the following opcode was XOR:

```python
C = 0
while code[pc] == 0x01 and code[pc + 2] == 0x05:
    C ^= code[pc + 1]
    pc += 3
```

This combines the XOR constants while leaving the rotation amount for the next parsing step.

We also avoided treating every byte matching a jump or return opcode as an instruction. Immediate values can contain those same bytes; a disassembler has to advance by each instruction's actual length.

### 5. Recover the chain

For each parsed block, the solver undid ADD or SUB, rotated right, and removed the XOR constants. From the second byte onward, it also used the previously recovered byte:

```python
# opadd is 0x03 for ADD or 0x04 for SUB.
T = (E - A) & 0xff if opadd == 0x03 else (E + A) & 0xff
value = ror8(T, r) ^ C
if i > 0:
    value ^= solved[i - 1]
solved.append(value)
```

The corrected parser recovered all 50 bytes. The final output in the shared solve record was:

```text
hit op 0xa at 0x475 after 50 constraints
constraints solved: 50
len: 50
Flag: b'nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}'
Str : nexsec26{th15_byt3_i5_b4k3d_n0t_fry3d_xD_ZXJ6eQ==}
```

The `hit op 0xa` line came from the parser reaching the end of the check blocks in a linear scan. It was not a rejection message from the original VM: that parser skipped jump instructions rather than executing the final branch.

The recovered answer is 50 bytes long, matching the header. The supplied record shows the successful recovery; it does not include a separate submission-acceptance message.
