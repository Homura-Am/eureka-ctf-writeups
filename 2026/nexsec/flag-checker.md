# Flag Checker (RE): Write-up

**Flag:** `nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}`

The archive contained a PS5 homebrew application. Instead of running the game, we followed its input handling to the flag checker and turned the checks into equations.

### 1. Extract the archive

The ZIP uses AES encryption, shown as compression method 99. Ordinary `unzip` could not extract it, so we used the challenge password with `pyzipper`:

```python
import pyzipper

with pyzipper.AESZipFile('d4d50977-flagchecker.zip') as archive:
    archive.setpassword(b'1f315b89b575d6cf8cdf093a6184a956')
    archive.extractall('.')
```

The main file was `flagchecker/eboot.bin`, a FreeBSD x86-64 ELF. Its `param.json` named the application “Flag Checker VI”.

### 2. Work out the imports

The import names looked like `4wSze92BhLI#B#B`. These are PS4/PS5 NIDs: hashed names used to identify imported functions.

The NID calculation uses the first eight bytes of SHA-1 over the function name followed by the salt `518D64A635DED8C1E6B039B1C3E55230`, reversed and Base64-encoded. Checking `sceKernelUsleep` gave `1jfXLRVzisc`, which matched the binary.

Resolving the 45 NIDs revealed functions such as `scePadInit`, `scePadOpen`, `scePadReadState`, `sceUserServiceGetInitialUser`, and `sceVideoOutOpen`. This told us to look for controller input rather than keyboard input.

### 3. Follow the controller input

The `DT_RELA` table had 45 relocation entries mapping GOT slots to NIDs. The import stubs at `0x472d`–`0x4835` were `jmp [GOT]` trampolines, called with direct `call rel32` instructions.

Following these calls led to `scePadReadState` at `0xe0f`, inside the input loop. Output used `sceKernelWrite`.

The loop at `0xd80`–`0x1200` implemented an on-screen keyboard:

| Input | Bit | Action |
| --- | --- | --- |
| Directional input | `0x10/0x20/0x40/0x80` | Move the cursor around the wrapping grid |
| Cross | `0x4000` | Add the selected character |
| Circle | `0x2000` | Backspace |
| Triangle | `0x1000` | Clear the input |
| Square | `0x8000` | Submit |

The buffer allowed up to 95 characters. Submitting called `0x2ae0` with the input and its length.

### 4. Find the real checker

The function at `0x2ae0` was only a trampoline:

```asm
lea rax, [rip-0x29f7]
jmp rax
```

It jumped to `0xf0`, where the actual checks started. The first condition required exactly `0x28`, or 40, characters.

The remaining code applied 65 equations to the input bytes. They mixed `xor`, `or`, `and`, `add`, `sub`, and `imul`, including 32-bit wraparound. Each failed comparison jumped to `0x9b2`, so a valid input had to pass every equation. The final comparison checked against `0x64` and returned the result through `sete al`.

### 5. Solve the equations

The instructions between `0xf0` and `0x9c3` were simple enough to lift symbolically. The solver tracked registers as 64-bit Z3 bitvectors, the input as 40 symbolic bytes, and stack slots by offset. Each `jne 0x9b2` added an equality constraint for the successful path.

This produced 65 constraints, matching the 65 guarded checks. Restricting the input bytes to printable ASCII gave:

```text
nexsec26{c4n_w3_pl4y_gta6_0n_w1nd0w5???}
```

The result is 40 characters long, matching the check at the start.
