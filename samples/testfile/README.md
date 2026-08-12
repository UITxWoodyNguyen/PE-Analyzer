# Harmless PE Analyzer lab sample

`pe_analyzer_lab_sample.c` is a benign Windows program for validating PE-analysis tooling. It prints its executable path and process ID, writes `pe_analyzer_lab_marker.txt` in the current directory, and exits.

It contains no malware behavior: no persistence, evasion, networking, privilege manipulation, process injection, or destructive actions.

## Build on Kali Linux

Install the MinGW-w64 cross compiler:

```bash
sudo apt update
sudo apt install -y mingw-w64
```

Build a 64-bit Windows PE executable:

```bash
x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra \-o pe_analyzer_lab_sample.exe pe_analyzer_lab_sample.c
```

Optional 32-bit build:

```bash
i686-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra \-o pe_analyzer_lab_sample_x86.exe pe_analyzer_lab_sample.c
```

## Inspect in Kali

```bash
file pe_analyzer_lab_sample.exe
objdump -x pe_analyzer_lab_sample.exe | less
sha256sum pe_analyzer_lab_sample.exe
```

Run it only in a Windows VM or Windows-compatible test environment; it creates just the marker text file in its working directory.