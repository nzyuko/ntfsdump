# ntfsdump Blog Plan

Working title: `ntfsdump: Acquiring Locked Windows Files With Raw NTFS`

The post should introduce the tradecraft concept first. Windows keeps registry hives such as `SAM` and `SYSTEM` locked during normal operation, so a red team or analyst sometimes needs an acquisition path that does not depend on `reg.exe`, Volume Shadow Copy, or a framework command shell. Keep the language practical and beginner-friendly: this is about why protected files are hard to copy, what raw NTFS reading changes, and what `ntfsdump` does.

The screenshots should drive the article. Capture a Windows Server lab run showing the binary help output, a `dump --out` execution, the resulting `SAM` and `SYSTEM` files in the output directory, and a simple file size/hash check to show that the output is real hive data. A second short sequence can show `--security` and the `read --out` mode. Avoid screenshots of host-specific folder names unless the text explains them as examples.

The article should clearly say that `ntfsdump` came from Missile's `ntfs_copy` / `ntfs_read` work, not a literal `samdump` command. Missile can be referenced as the original framework context, while `ntfsdump` should stand on its own as the small tool people can understand quickly.

Do not make the post about hash extraction. The first version is acquisition only. If parser work is added later, that can be a separate post.
