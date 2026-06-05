# ntfsdump

Raw NTFS file acquisition for Windows.

`ntfsdump` copies protected Windows files by resolving paths through NTFS metadata and reading file bytes from the raw volume. It has built-in commands for local registry hives, generic modes for copying or reading arbitrary absolute paths, and a SAM parser for copied hive files.

The default `dump` command acquires `SAM` and `SYSTEM`; `SECURITY` can be included with `--security`.

## Requirements

- Windows target host
- NTFS volume
- Administrator-level privileges for raw volume access

## How It Works

`ntfsdump` opens the raw volume, walks NTFS metadata, resolves the target path through the MFT, locates the file data, and writes those bytes to disk. Raw volume access requires administrator-level privileges.

## Commands

| Command | Use |
| --- | --- |
| `dump` | Acquire `SAM` and `SYSTEM`; add `--security` to include `SECURITY`. |
| `copy` | Copy one or more protected files through the raw NTFS path. |
| `read` | Read one protected file and print base64, or write raw bytes with `--out`. |
| `sam` | Parse a copied `SAM` hive and print local account entries with sensitive values redacted. |

## Build

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

The Windows binary is written to:

```text
target/x86_64-pc-windows-gnu/release/ntfsdump.exe
```

## Usage

Acquire `SAM` and `SYSTEM`:

```powershell
.\ntfsdump.exe dump --out C:\ProgramData\ntfsdump
```

Acquire `SAM`, `SYSTEM`, and `SECURITY`:

```powershell
.\ntfsdump.exe dump --out C:\ProgramData\ntfsdump --security
```

Copy a specific protected file:

```powershell
.\ntfsdump.exe copy --out C:\ProgramData\ntfsdump C:\Windows\System32\config\SAM
```

Read one protected file and print base64:

```powershell
.\ntfsdump.exe read C:\Windows\System32\config\SAM
```

Read one protected file and write raw bytes:

```powershell
.\ntfsdump.exe read C:\Windows\System32\config\SAM --out C:\ProgramData\ntfsdump\SAM
```

Parse a copied SAM hive:

```powershell
.\ntfsdump.exe sam C:\ProgramData\ntfsdump\SAM
```

## Example Output

```powershell
PS C:\ProgramData\ntfsdump> .\ntfsdump.exe dump --out .\out --security
[+] SAM -> .\out\SAM (65536 bytes)
[+] SYSTEM -> .\out\SYSTEM (15204352 bytes)
[+] SECURITY -> .\out\SECURITY (65536 bytes)

PS C:\ProgramData\ntfsdump> Get-ChildItem .\out

Name       Length LastWriteTime
----       ------ -------------
SAM         65536 6/4/2026 7:32:22 AM
SECURITY    65536 6/4/2026 7:32:22 AM
SYSTEM   15204352 6/4/2026 7:32:22 AM

PS C:\ProgramData\ntfsdump> .\ntfsdump.exe sam .\out\SAM
[+] Parsed 3 local accounts
RID        Username                         LM          NT          Records
--------   ------------------------------   ---------   ---------   -------
0x000001F4 Administrator                    -           [redacted]   V=246 F=80
0x000001F5 Guest                            -           [redacted]   V=230 F=80
0x000003E9 local.user                       -           [redacted]   V=240 F=80
```

## Related Write-Up

Lab screenshots and notes:

https://zer0.art/2026/06/04/ntfsdump-raw-ntfs-hive-acquisition/

## Credits

The raw NTFS parsing approach credits AxiomSecrets.
