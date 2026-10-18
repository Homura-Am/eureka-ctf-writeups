# Dead Drop Latte (Forensics): Write-up

**Flag:** `nexsec26{l3ts_buy_s0me_c0ffee_2_stay_awake}`

The capture led from a fake coffee website to a downloaded executable and then to encrypted callback traffic. The flag was in one of those callbacks, so we needed both the encryption format and the right key.

### 1. Follow the fake verification prompt

The coffee website presented a human-verification message that told the visitor to run a PowerShell command. That command downloaded `clientverify.exe`.

In Wireshark, we followed the HTTP traffic to connect the verification prompt to that executable:

```text
http
```

The exact download command and server address were not preserved in the supplied solve notes, but the filename linked the website activity to the next artifact.

### 2. Find the callback format

Strings in the executable revealed AES-256-GCM encryption, Base64 transport encoding, and the additional authenticated data `brew-v1`.

The message layout was:

```text
Base64(IV || ciphertext || authentication tag)
```

The exact bytes of `brew-v1` had to be supplied during decryption because the additional data is authenticated along with the ciphertext.

### 3. Collect keys from DNS

DNS TXT responses supplied the candidate keys. We located them using:

```text
dns.qry.type == 16
```

The DNS responses and callback messages had to be considered together: one provided candidate keys, and the other contained the encrypted data.

### 4. Match the keys to the messages

For each callback, we Base64-decoded the data, split the IV, ciphertext, and tag, then tried the candidate keys with AAD `brew-v1`.

GCM authentication told us whether a candidate worked. A failed tag check meant a key or another input was wrong; a successful check confirmed the plaintext under those inputs.

The original IV and tag lengths were not preserved in the notes. Those offsets should be taken from the executable's implementation rather than guessed.

### 5. Read sequence 3

The callback with sequence number 3 decrypted to JSON. Its `note` field held the flag:

```json
{
  "note": "nexsec26{l3ts_buy_s0me_c0ffee_2_stay_awake}"
}
```

This is the relevant field from the recovered message, rather than the complete JSON object.
