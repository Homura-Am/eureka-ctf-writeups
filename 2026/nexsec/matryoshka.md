# matryoshka (RE): Write-up

**Flag:** `nexsec26{nexsec26{nexsec26{🚩}}}`

The program wanted a 16-character secret. We recovered it by opening 30 encrypted dolls inside the executable, without running the file itself.

### 1. Look inside the program

`matryoshka.exe` was a .NET program, so its metadata and instructions could be examined statically.

It contained two encrypted blobs, doll-0 and doll-1, each about 116 KB. Its strings were scrambled by XORing every byte with its position and `0xAA`.

Undoing that revealed the story text, the blob names, and four 64-character hexadecimal strings. Three strings were used to derive the first keys; the fourth was the hash of the final secret.

### 2. Derive the first keys

The program XORed the three key strings together, appended `0` for doll-0 or `1` for doll-1, and hashed the result with SHA-256. That produced an AES-256 key.

The first 16 bytes of each blob were its IV. Decrypting the rest with the derived key produced a valid .NET file for each doll, which confirmed the key recipe.

### 3. Open the nested dolls

Each decrypted doll contained its path, the input positions it checked, a hash for each position, and two smaller dolls.

A child's key was SHA-256 of its parent's key followed by the child's path. The keys did not depend on the supplied secret, so we could decrypt the whole tree before knowing the answer.

There were four levels:

```text
2 + 4 + 8 + 16 = 30 dolls
```

Each level doubled the number of dolls and halved the number of positions guarded by each one. The 16 innermost dolls each checked one character.

### 4. Recover each character

An innermost doll checked an HMAC-SHA256 value over two bytes: the input position and its expected character, using that doll's key.

There were only 256 possible byte values for each character. Trying them against the stored HMAC gave exactly one match per position. Together, the matches gave:

```text
rhkaDwfinMePcolz
```

### 5. Decrypt the flag and check the secret

Only the innermost doll at path `1111` contained the encrypted flag. Its key was SHA-256 of the recovered secret. Decrypting it gave the flag shown above.

The secret's SHA-256 matched the value stored in the program:

```text
77aa4d230ca164172ea2c972e207cb93dae2d0bd5e5fd3234ff4b5ea8874e345
```

Replaying the program's logic in Python with the correct secret passed through every doll, printed the story, and ended with the flag. Changing the last character stopped the process with:

```text
Another stranger. My seam stays shut.
```
