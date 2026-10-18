# VeryFest (Misc): Write-up

**Flag:** `nexsec26{decentralization_means_giving_up_dominance_over_security}`

The flag was stored in pieces inside the contract bytecode. The main job was to make that bytecode readable and find the comparison.

### 1. Disassemble the file

The `.evm` file was Ethereum Virtual Machine bytecode written as hexadecimal. The README pointed to `re.hanz.dev`, which hinted that we should disassemble it.

A short disassembler turned the bytes into instructions such as `PUSH32`, which puts a 32-byte value on the stack, and `EQ`, which compares values.

### 2. Identify the functions

The first part of the code read the first four bytes of the request and compared them against three selectors. The original function names were not present, so we labelled them by their behavior:

| Selector | Our label | Behavior |
| --- | --- | --- |
| `0xd99a8dc3` | submit | Check the supplied text |
| `0x799320bb` | isSolved | Report whether a correct answer has been submitted |
| `0x146e61ed` | attempts | Report the number of attempts |

### 3. Read the comparison

The submit function first checked for a 66-byte input. It then compared the input against three pieces stored directly in the code with `PUSH32` and `PUSH2` instructions.

| Piece | Bytes | Decoded text |
| --- | --- | --- |
| 1 | 32 | `nexsec26{decentralization_means_` |
| 2 | 32 | `giving_up_dominance_over_securit` |
| 3 | 2 | `y}` |

Joining them gives the flag. The lengths add up to `32 + 32 + 2 = 66`, which matches the input-length check.

### 4. Check the result

The bytecode was tested in a small interpreter. An input with the wrong length was rejected, and a 66-byte input with one wrong character was also rejected.

The joined string was accepted. Afterward, `isSolved` returned true and the contract emitted its success event.
