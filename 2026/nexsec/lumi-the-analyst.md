# Lumi the Analyst (OT / ICS): Write-up

**flag:** `nexsec26{XIO_I_1_0_XIC_I_1_3_6F3A91D4}`

The grinder's guard door was supposed to stop the motor whenever it opened. The challenge said exactly one input contact in the Motor_Run rung had changed from the approved 2021 program.

The important part was proving the change from the running system. A single read could show the motor and door states, but would not explain which contact was actually controlling the rung.

### 1. Start with the baseline

The challenge provided `grinder_guard_export.txt` and `modbus_point_map.md`, along with a Modbus/TCP endpoint at `koala.nexsec.my:39007`.

The baseline contact identified by the final match was:

```text
XIO I:1/0
```

XIO is true when its addressed bit is zero. With `I:1/0` representing GuardDoor_Open, this contact permits the rung when the door-open bit is zero.

The initial theory was that the instruction had simply been inverted on the same input. The live result showed that the address had changed too.

### 2. Poll the live sequence

The successful run connected to the challenge service and polled its test sequencer for approximately 25 seconds:

```text
[+] Connected to koala.nexsec.my:39007
[+] Resident Checksum: 6F3A91D4

Polling live test sequencer for ~25 seconds...
```

Repeated observations matter because Motor_Run uses a seal-in rung. Its state depends on the permissive contacts, the start input, and its previous state. Several test steps give more information than one snapshot.

The shared notes describe discrete inputs at addresses 0–5, Motor_Run at coil 0, and diagnostic holding registers starting at address 0. Equivalent individual reads with mbpoll are:

```bash
# Discrete inputs, FC02
mbpoll -m tcp -p 39007 -a 1 -0 -1 -t 1 -r 0 -c 6 koala.nexsec.my

# Output coils, FC01
mbpoll -m tcp -p 39007 -a 1 -0 -1 -t 0 -r 0 -c 4 koala.nexsec.my

# Holding registers, FC03
mbpoll -m tcp -p 39007 -a 1 -0 -1 -t 4 -r 0 -c 4 koala.nexsec.my
```

These commands illustrate the read types; the supplied successful output came from the polling script. Its source and individual samples were not included.

For mbpoll, `-t 1` selects discrete inputs and `-t 0` selects coils. `-0 -r 0` starts at protocol address zero, while `-1` performs one poll. When grouping separate reads, samples crossing a sequencer-step boundary should be discarded so they are not treated as simultaneous.

### 3. Identify the changed contact

After polling, the solver reported:

```text
[+] Analyzing rung logic against live sequence...
    MATCH FOUND -> nexsec26{XIO_I_1_0_XIC_I_1_3_6F3A91D4}
```

That result identifies both changes:

| Version | Instruction | Address |
| --- | --- | --- |
| Approved baseline | XIO | `I:1/0` |
| Live match | XIC | `I:1/3` |

XIC is true when its addressed bit is one. The matched live rung therefore checks input 3 instead of checking that the guard-door input is zero.

This explains why the same-address inversion theory was incomplete. Replacing `XIO I:1/0` with `XIC I:1/3` removes the direct guard-door check at that position. Whether the replacement contact passes now depends on input 3.

### 4. Include the resident checksum

The successful output reported the resident checksum as:

```text
6F3A91D4
```

The shared point-map notes describe the checksum as two 16-bit holding-register words, high word first. The reconstruction is:

```python
resident_checksum = ((high_word & 0xffff) << 16) | (low_word & 0xffff)
print(f'{resident_checksum:08X}')
```

The checksum identifies the running program associated with the result. The sequence comparison identifies the changed contact; the checksum alone would not establish the logic change.

### 5. Format the flag

The required fields are the baseline instruction and address, the live instruction and address, and the resident checksum. Colons and slashes in addresses become underscores.

Using the matched values gives:

```text
nexsec26{XIO_I_1_0_XIC_I_1_3_6F3A91D4}
```

The captured output records a solver match and the recovered flag. A separate submission-acceptance message was not supplied.

### Command reference

[mbpoll documentation](https://github.com/epsilonrt/mbpoll/blob/master/README.md) describes the read types, zero-based addressing, and one-poll option used above.
