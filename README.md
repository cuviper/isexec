# isexec

Program to determine whether the file behind a given path is a valid executable.

Heuristics for determining valid executables include support for:

- ELF binaries (with `0x7F` `ELF` magic number)
- PE / MZ binaries (with `MZ` magic number)
- valid executable scripts (with `#!` magic number and valid shebang)

