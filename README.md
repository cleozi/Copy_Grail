# copygrail

**copygrail** is a compact, single-file C++ implementation of the CVE-2026-31431 ("Copy Fail") local privilege escalation vulnerability.

It showcases a clean AF_ALG + `splice()` page cache corruption technique that can be used to overwrite a setuid binary and escalate privileges to root on vulnerable Linux systems.

The project was built with simplicity and portability in mind — no bloated codebase, no unnecessary dependencies, just a straightforward proof-of-concept written in modern C++.

## ⚠️ Legal Disclaimer

This project is intended **only for educational purposes, security research, and authorized penetration testing**.

Do not run this against machines you do not own or have explicit permission to test. Misuse of this software may violate local laws and regulations. The authors assume no responsibility for any damage or illegal use.

## Features

- Single-file source code
- Modern, readable C++ implementation
- Minimal external dependencies
- Statically compiled binary for portability
- Documented internals for easier research and learning

## Requirements

- A Linux kernel vulnerable to CVE-2026-31431
- `g++` with C++11 support or newer
- zlib development headers

Debian/Ubuntu:

```bash
sudo apt install zlib1g-dev
```

## Build
```
g++ -O2 -static -o copygrail copygrail.cpp -lz
```

## Run
```
./copygrail
```
