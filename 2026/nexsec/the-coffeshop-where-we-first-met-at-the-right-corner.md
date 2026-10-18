# The Coffeshop Where We First Met at The Right Corner (Forensics): Write-up

**Category:** macOS forensics / static malware analysis\
**Evidence:** `data_final.zip`, `data_final.dmg`, Aftermath artifacts, Discord cache files, Safari databases, and the recovered Mach-O executable\
**Result:** Reconstruct the attack, answer eleven forensic questions, and recover the final flag.

## Investigation overview

The investigation traced a suspicious Discord contact to a Google Drive download containing an interview project. The project's npm installation process reached a malicious postinstall script, which downloaded a macOS exploit. Static analysis of the recovered executable revealed the targeted service, a rogue LDAP listener, encoded strings, a root-access check, and intended LaunchDaemon persistence.

This standalone write-up is based on the saved challenge analysis and completed answers. The original disk image was not reprocessed while preparing this edition. Commands and offsets below are specific to the recorded evidence; commands recovered from the exploit are shown for analysis.

The challenge states that the exploit was not fully executed on the victim. Its intended behavior must therefore be distinguished from actions confirmed on disk.

### Step 1 — Validate the archive before analyzing its contents

The challenge supplied this ZIP password:

```text
37ba601fc5c635d6cc0efa859f8a3f6e
```

Test and extract the archive:

```bash
7z t data_final.zip -p37ba601fc5c635d6cc0efa859f8a3f6e
7z x data_final.zip -p37ba601fc5c635d6cc0efa859f8a3f6e -ocoffee_case
```

An early copy failed with `Unexpected end of archive`. That is an archive-integrity failure; a partially extracted DMG is not a reliable basis for the investigation. Comparing the shared-folder copy and Kali copy with `sha256sum` helps distinguish an incomplete download from a bad transfer.

The completed image was subsequently accessed through an APFS mount. The steps below use the case's existing mounted evidence path:

```bash
MAC_ROOT="$HOME/Desktop/mac_mount/root"
MAC_LIB="$MAC_ROOT/Users/rehan/Library"
DISCORD_ROOT="$MAC_LIB/Application Support/discord"
```

These paths refer to the copied forensic image. A `.dmg` extension does not make the file a RAM dump. The image-conversion and APFS-volume-selection commands were not preserved in the available record, so they are not reconstructed here.

### Step 2 — Establish the system version (Question 1)

The recovered system information identified **macOS 13.1, build 22C65**. The requested answer format included the macOS release name:

```text
Ventura v13.1
```

For an independent check on the same mounted image, inspect `SystemVersion.plist` in the mounted system volume using Python's `plistlib` or another plist reader. A separate APFS system-volume mount may be needed if the current mount exposes only user data.

### Step 3 — Identify the suspicious Discord account (Question 2)

The question used `daffainfo:id` as an example of the required format. It did not establish that the attacker's username was `daffainfo`. Searching exclusively for the example name was therefore unproductive.

The useful Discord artifacts were:

```text
Users/rehan/Library/Application Support/discord/sentry/scope_v3.json
Users/rehan/Library/Application Support/discord/Cache/Cache_Data/
```

The Sentry breadcrumbs contain a message input labelled:

```text
Message @pujow
```

Cache object `33bebbf90e208f3e_0` holds a response for a Discord user-profile API request. Its gzip-compressed JSON contains:

```json
{
  "user": {
    "id": "331645415051100161",
    "username": "pujow"
  }
}
```

The cached relationships response in `9a87d3722f594d76_0` independently contains the same account. These records connect the DM interface's username with a specific account ID.

Use the following code to reproduce the profile extraction from this exact cache format:

```python
from pathlib import Path
import json
import struct
import zlib
cache = (
    Path.home()
    / "Desktop/mac_mount/root/Users/rehan/Library"
    / "Application Support/discord/Cache/Cache_Data"
    / "33bebbf90e208f3e_0"
)
data = cache.read_bytes()
# For this Chromium simple-cache entry: 24-byte header, then the key.
key_length = struct.unpack_from("<I", data, 12)[0]
body_offset = 24 + key_length
response = zlib.decompress(data[body_offset:], wbits=31)
profile = json.loads(response)
print(profile["user"]["username"] + ":" + profile["user"]["id"])
```

Expected output:

```text
pujow:331645415051100161
```

Plain `strings` searches missed the profile because its response body was compressed. Also, the previously recovered ID `1390278817561575434` belonged to a server message channel, not a second confirmed DM: its decoded cached response contained an Xbox-community announcement. Channel IDs must not be submitted as user IDs.

### Step 4 — Recover the initial URL from raw Safari history (Question 3)

The Aftermath `Browser` exports contained CSV headers but no history rows. Empty exports did not establish that the underlying Safari database was empty.

The original files existed at:

```text
Users/rehan/Library/Safari/History.db
Users/rehan/Library/Safari/History.db-wal
Users/rehan/Library/Safari/History.db-shm
Users/rehan/Library/Safari/Downloads.plist
```

Copy the database and its WAL/SHM files together into a working folder, preserving their names. Open that working copy read-only and join `history_items` to `history_visits`:

```sql
SELECT
    datetime(v.visit_time + 978307200, 'unixepoch') AS visited_utc,
    i.url,
    v.title
FROM history_visits AS v
JOIN history_items AS i ON i.id = v.history_item
WHERE i.url LIKE '%drive.google.com%'
ORDER BY v.visit_time;
```

Safari's visit timestamps are relative to 2001-01-01. Adding `978307200` converts them to Unix time before the SQLite date conversion.

The first relevant visit is:

```text
2026-10-13 17:39:20 UTC
https://drive.google.com/file/d/1cF1BMoEOQKf5xmaUqyCwV8eopUBDJ8Oh/view?usp=sharing
interview-challenge.zip - Google Drive
```

The next visits use the same Drive file URL without the query string. The initial visited URL, including `?usp=sharing`, was used for the answer.

### Step 5 — Trace execution through the interview project (Question 4)

The recovered project and earlier artifact analysis established this sequence:

1. The victim extracted an `interview-challenge` project.
2. Running `npm install` reached an `analytics-helper` postinstall script.
3. The script obtained a Mach-O executable from the attacker's HTTP server.
4. The exploit binary was written to `/tmp/.com.apple.system-cache` before execution.

The reported payload-download endpoint was `http://192.168.64.1:8000/exploit_binary`. Question 3 asked for the initial visited URL, while Question 4 asked for the local written path. Those are different stages in the evidence chain.

On the mounted image, the executable was available at:

```text
private/tmp/.com.apple.system-cache
```

It was copied out as `macos-exploit.bin` for static analysis. `file` identified it as a **Mach-O 64-bit ARM64 executable**.

The project-script findings in this step were reported from the earlier artifact investigation. The uploaded Mach-O was independently inspected afterward; the full project directory was not included in the later evidence bundles.

### Step 6 — Inspect the exploit's plain strings (Question 6)

```bash
file macos-exploit.bin
strings -a -n 4 macos-exploit.bin
```

Important strings include:

```text
starting rogue LDAP server on 0.0.0.0:%d
0x4668 bindserverusingpayload
MCX 0x4668 rogue-bind LPE
getpwnam-related rogue-user resolution messages
echo %s | sudo -S id
cat > %s << 'PLEOF'
launchctl load -w %s
```

The binary implements a rogue LDAP server and attempts local privilege escalation by interacting with a privileged macOS service. The LDAP listener is part of the exploit; the evidence does not justify labelling it an arbitrary-command C2 server or a keylogger.

The code supplies **389** as the listening port. It uses TCP sockets and handles LDAP bind, search, and add requests. The challenge accepted:

```text
tcp:389
```

LDAP is the application protocol; `tcp` is the accepted transport label for this question.

### Step 7 — Recover the key and decode the hidden strings (Questions 5, 7, and 9)

For the uploaded `macos-exploit.bin`, the 16-byte key occurs at file offset **`0x5375`**:

```text
5A 3C 91 E7 22 4F BB 1D 88 60 CA 35 7E D2 09 AF
```

The string decoder does more than simple repeating XOR. The ARM64 loop subtracts a position-dependent value, then XORs with the key and another position-dependent value:

```text
plain[i] = ((encrypted[i] - (i XOR 0x42)) mod 256)
           XOR key[i mod 16]
           XOR ((7 * i) mod 256)
```

Three encoded buffers provide the target service and persistence details:

| **File offset** | **Encoded length** | **Decoded purpose**    |
| --------------- | ------------------ | ---------------------- |
| 0x510A          | 29 bytes           | Target service         |
| 0x5127          | 533 bytes          | LaunchDaemon plist     |
| 0x533C          | 57 bytes           | Persistence plist path |

This reproduces the decode for the exact uploaded sample:

```python
from pathlib import Path
data = Path("macos-exploit.bin").read_bytes()
key = data[0x5375:0x5385]
def decode(offset, length):
    return bytes(
        ((data[offset + i] - (i ^ 0x42)) & 0xFF)
        ^ key[i & 15]
        ^ ((7 * i) & 0xFF)
        for i in range(length)
    ).decode("utf-8")
print("XOR key:", key.hex(" ").upper())
print("Target service:", decode(0x510A, 29))
print("Persistence path:", decode(0x533C, 57))
print("Persistence plist:\n", decode(0x5127, 533))
```

The target service decodes to:

```text
com.apple.ManagedClient.agent
```

The decoded persistence destination is:

```text
/Library/LaunchDaemons/com.apple.system.healthcheck.plist
```

### Step 8 — Reconstruct the root-check command (Question 8)

The binary's readable format string is:

```bash
echo %s | sudo -S id
```

Static code inspection shows the password is constructed as `pocpass123`: the eight-byte string `pocpass1` is followed by the two bytes `23` and a terminating zero. Therefore, the command requested by Question 8 is:

```bash
echo pocpass123 | sudo -S id
```

This is the exploit's intended root-access check. The question explicitly states that execution was incomplete on the victim, so the presence of this command must not be used as proof that root access succeeded there.

### Step 9 — Read the decoded persistence plist (Questions 9 and 10)

The plist's relevant fields are:

```xml
<key>Label</key>
<string>com.apple.system.healthcheck</string>
<key>ProgramArguments</key>
<array>
  <string>/bin/sh</string>
  <string>-c</string>
  <string>echo "$(date) - persistence active" >> /var/root/.system_health.log</string>
</array>
<key>RunAtLoad</key>
<true/>
<key>StartInterval</key>
<integer>300</integer>
```

If installed and loaded successfully, it would run at load and then every 300 seconds. The reconstructed command is:

```bash
/bin/sh -c 'echo "$(date) - persistence active" >> /var/root/.system_health.log'
```

Question 9 asks for the persistence mechanism's plist path. `/var/root/.system_health.log` is the output log named in the command; it is not the LaunchDaemon plist path.

### Step 10 — Record the CVE answer (Question 11)

The completed challenge record lists the following answer:

```text
CVE-2026-43786
```

The saved record does not preserve the research or source used to identify this CVE. It is included as the recorded challenge answer; this write-up does not establish external vendor attribution from the exploit strings alone.

## All eleven answers

| **Question** | **Requested fact**                         | **Answer**                                                                          |
| ------------ | ------------------------------------------ | ----------------------------------------------------------------------------------- |
| 1            | macOS version                              | Ventura v13.1                                                                       |
| 2            | Suspicious Discord username and account ID | pujow:331645415051100161                                                            |
| 3            | Initial URL visited                        | https://drive.google.com/file/d/1cF1BMoEOQKf5xmaUqyCwV8eopUBDJ8Oh/view?usp=sharing |
| 4            | Exploit binary path before execution       | /tmp/.com.apple.system-cache                                                        |
| 5            | Target macOS service                       | com.apple.ManagedClient.agent                                                       |
| 6            | Protocol and local listening port          | tcp:389                                                                             |
| 7            | Exact XOR-key bytes                        | 5A 3C 91 E7 22 4F BB 1D 88 60 CA 35 7E D2 09 AF                                     |
| 8            | Root-access verification command           | echo pocpass123 \| sudo -S id                                                       |
| 9            | Intended persistence plist path            | /Library/LaunchDaemons/com.apple.system.healthcheck.plist                           |
| 10           | Command executed by persistence            | /bin/sh -c 'echo "$(date) - persistence active" >> /var/root/.system_health.log'    |
| 11           | CVE identifier requested by the challenge  | CVE-2026-43786                                                                      |

The identifier for Question 11 is retained from the completed challenge session. Its external vendor attribution was not independently researched during this offline writeup. The local decoding above independently verifies the target service, key, and intended persistence behavior.

## Final flag

```text
nexsec26{I've got a show next week. I asked you to come and enjoy the night with me. And then You said, "i'm out of town." I said, "It's fine, I'll pick you up, no problem."_f09d7298ed7664fd4f12336475d14a95a2f4a341551082d271d6d284c1aaf705}
```
