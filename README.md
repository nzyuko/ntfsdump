# ntfsdump

`ntfsdump` is a standalone Windows protected-file acquisition tool built from the raw NTFS reader in Missile. The Missile workflow was not a separate `samdump` command in this checkout; the useful part lived behind `ntfs_copy` and `ntfs_read`, normally pointed at locked hives such as `C:\Windows\System32\config\SAM` and paired with `SYSTEM`.

The tool keeps that primitive and gives it a cleaner shape. `dump` acquires `SAM` and `SYSTEM` by default, with `SECURITY` available when it is useful for the engagement or lab. The acquisition path reads the NTFS volume directly, resolves the target file through MFT records, and writes the bytes without shelling out to `reg.exe`.

## Build

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

The Windows binary is written to:

```text
target/x86_64-pc-windows-gnu/release/ntfsdump.exe
```

## Usage

Acquire the standard local-account hives:

```powershell
.\ntfsdump.exe dump --out C:\ProgramData\ntfsdump
```

Acquire `SAM`, `SYSTEM`, and `SECURITY`:

```powershell
.\ntfsdump.exe dump --out C:\ProgramData\ntfsdump --security
```

Copy another protected file through the same raw NTFS path:

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

## Notes

`ntfsdump` is an acquisition tool, not a hash parser. The first version focuses on reliably acquiring protected hive files in an authorized Windows environment. A parser layer can be added later if the standalone tool should include offline analysis as well as acquisition.

The raw NTFS reader is ported from Missile's `ntfs_copy` module, which itself credits AxiomSecrets for the original NTFS parsing approach.
