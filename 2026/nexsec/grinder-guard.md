# Bench Grinder GR-3 (OT / ICS): Partial write-up

**Status:** Partial — the shared notes contain a proposed method, but no live capture or confirmed flag.

The challenge says the grinder should stop when its guard door opens. Exactly one input contact in the Motor_Run rung differs from the approved 2021 baseline. We need to identify that contact and prove the change using the running system.

The important warning in the description is “one read proves nothing.” A single input/output snapshot cannot establish which contact was changed.

### 1. Establish the baseline

The challenge provides `grinder_guard_export.txt` and `modbus_point_map.md`. The shared conversation names these files, but does not expose their contents, so the original rung and point map still need to be checked.

The notes propose the following input interpretation:

| Address | Symbol | Expected permissive state |
| --- | --- | --- |
| `I:1/0` | GuardDoor_Open | 0: door closed |
| `I:1/1` | EStop_Pressed | 0: emergency stop released |
| `I:1/2` | Local_Mode | 1: local mode |
| `I:1/5` | ThermalOL_Trip | 0: no overload |

They also identify `I:1/4` as the momentary start input.

Under that interpretation, XIO contacts would pass the three active-high fault inputs when their bits are zero, while XIC would pass Local_Mode when its bit is one. This is a working hypothesis from the notes, not a verified transcription of the baseline.

### 2. Read the inputs, output, and diagnostic registers

The challenge endpoint in the conversation is `koala.nexsec.my:39007`, using Modbus/TCP.

The proposed mapping is:

| Function | Zero-based addresses | Meaning in the notes |
| --- | --- | --- |
| FC02 | 0–5 | Inputs `I:1/0` through `I:1/5` |
| FC01 | 0–3 | Output coils, with coil 0 as Motor_Run |
| FC03 | 0–3 | Event counter, pattern step, checksum high word, checksum low word |

These commands are for collecting the missing evidence. They have not been executed as part of this write-up:

```bash
# FC02: discrete inputs
mbpoll -m tcp -p 39007 -a 1 -0 -1 -t 1 -r 0 -c 6 koala.nexsec.my

# FC01: output coils
mbpoll -m tcp -p 39007 -a 1 -0 -1 -t 0 -r 0 -c 4 koala.nexsec.my

# FC03: holding registers
mbpoll -m tcp -p 39007 -a 1 -0 -1 -t 4 -r 0 -c 4 koala.nexsec.my
```

The type selectors and starting address above correct the suggested commands in the conversation. For mbpoll, `-t 1` reads discrete inputs and `-t 0` reads coils. `-0 -r 0` starts at protocol address zero, and `-1` makes each invocation return after one poll.

Unit ID 1 and the point mapping are assumptions from the notes until the supplied map confirms them.

### 3. Compare behavior across the test pattern

The shared notes describe a repeating pattern with two-second steps and a step number in holding register 1.

Collect several complete cycles, recording the inputs, Motor_Run, step number, and event counter. Read the step number before and after each group of reads, and discard groups that cross a step boundary. This reduces the risk of comparing inputs from one test step with an output from another.

The rung also has a seal-in branch, so the previous Motor_Run state matters. Compare the full sequence with the baseline, including when the motor starts, remains on, and drops out.

The notes suggest watching for Motor_Run while GuardDoor_Open is one. That would demonstrate behavior inconsistent with the proposed door interlock, but would not by itself prove an XIO-to-XIC change at `I:1/0`. A different input address, another instruction change, or an incorrect point interpretation must be ruled out using the full trace.

Likewise, an increasing bypass-event counter supports an unsafe-condition finding only after its definition is confirmed. It does not independently identify the changed contact.

### 4. Recover the resident checksum

The proposed register map places the checksum's high word in `N7:2` and low word in `N7:3`:

```python
resident_checksum = ((n7_2 & 0xffff) << 16) | (n7_3 & 0xffff)
print(f'{resident_checksum:08X}')
```

The conversation lists `0x5C14A7B3` as the baseline checksum. That value still needs confirmation against the original baseline.

A different resident checksum would support a program-identity difference. It would not explain which contact changed; that requires the behavior comparison above.

### 5. Build the flag after confirming the change

The challenge gives this format:

```text
nexsec26{<baseline_instruction>_<baseline_address>_<live_instruction>_<live_address>_<resident_checksum>}
```

Replace `:` and `/` in addresses with underscores, for example `I:1/4` becomes `I_1_4`.

The shared conversation guesses XIO to XIC at `I:1/0`, but contains no live output proving that pair and no resident checksum. There is therefore no confirmed flag to record yet.

To finish the write-up, the missing evidence is the original baseline and point-map files, a multi-step live capture, and the resulting accepted flag.

### Command reference

[mbpoll documentation](https://github.com/epsilonrt/mbpoll/blob/master/README.md) describes the read types, zero-based addressing, and one-poll option used above.
