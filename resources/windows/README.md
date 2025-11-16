# Windows Baseline Repository

The `--windows-repair-*` commands expect a repository of clean operating-system files organised by manifest key. A typical layout looks like:

```
resources/windows/
  win10.manifest
  win10/
    System32/
      kernel32.dll
      ...
  win11.manifest
  win11/
    System32/
      kernel32.dll
      ...
```

* Each `<key>.manifest` is produced with `paranoid_av --windows-repair-capture <WindowsDir> <version> <build> <key> <output>`. The capture routine hashes files under `System32`, `SysWOW64`, and `WinSxS`, flags core extensions, and records sizes so audits can highlight drift.
* Store the corresponding clean binaries under `<key>/` preserving the Windows directory structure (e.g., `System32/`, `SysWOW64/`).
* During response the `--windows-repair-collect <repo> <output>` workflow copies the manifest-matched binaries into `<output>/` and saves an updated plan next to the staged files.

The manifests intentionally avoid shipping proprietary binaries. Populate this directory using a trusted golden image that matches your enterprise build baselines.
