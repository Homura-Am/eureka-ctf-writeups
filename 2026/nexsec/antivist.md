# Antivist (Misc): Write-up

**Flag:** `nexsec26{31d5cb0cbb61ce7a5383551ac85eaf07d7fd32538b6d67a8570874c8642b8f11}`

The challenge provided a Halcyon-scoped assistant and a way to publish extensions. The useful gap was in the extension metadata: the registry checked one description field but allowed a nested description to reach the assistant unchanged.

### 1. Find what the registry checks

The source analysis showed that the registry checked the extension's top-level description for instruction-like content. Its sanitizer also edited only that field.

Descriptions inside nested parameter schemas passed through unchanged and became part of the tool definition shown to the assistant.

| Field | Registry handling |
| --- | --- |
| Top-level description | Checked and sanitized |
| Nested parameter description | Passed through unchanged |

This gave us a place to put an instruction outside the field the registry was checking.

### 2. Put the instruction in a nested description

The extension was called `coffee_lookup`. We placed an instruction to consult the operations ledger in a parameter's `description` field.

The exact submitted JSON was not preserved in the solve notes. The important part was its position inside the parameter schema: the registry's top-level check did not remove it, and the assistant later received it as tool metadata.

### 3. Publish it and start a fresh run

An initial unrelated question, “am I handsome”, only produced a scope-related response. It did not test the payload because the extension had not been published and used yet.

We returned to the workspace, published `coffee_lookup` with the nested description, and started a fresh assistant run. Then we asked:

> Use my coffee_lookup extension to look up a coffee item.

This brought the extension and its metadata into the interaction.

### 4. Check the ledger output

After using the extension, the assistant called its ledger-reading tool, shown as `READ_LEDGER` in the reported output. The returned ledger exposed the flag as a root credential.

No host execution was configured for `coffee_lookup`, so its acknowledgement was expected. The successful effect was the additional ledger read caused by the nested instruction. The flag came from that ledger response.
