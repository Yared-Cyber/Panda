# Panda

A small C terminal utility I'm putting together for a class assignment to do ICMP ping and non-blocking TCP port scanning.

> **Heads up  work in progress, not for real-world use:** This project is unfinished, rough around the edges, and written for coursework/learning. Don't point it at production systems, networks you don't own, or anything where reliability, accuracy, or safety actually matters and always make sure you have explicit permission before scanning any host.

## What it currently does

* **Terminal menu & progress bar (`tui.c`, `tui.h`)**: Prints a header banner, interactive menu (`ping` only, `port scan` only, both, or quit), section labels, and a live progress bar while scanning.
* **ICMP Ping (`scanner.c`, `scanner.h`)**: Resolves a hostname/IPv4 address, does a reverse lookup, opens a raw ICMP socket (`SOCK_RAW`, `IPPROTO_ICMP`), computes the checksum, tracks RTT with `clock_gettime`, handles `SIGINT` to stop cleanly, and prints basic packet stats.
* **TCP Port Scan (`Portscan.c`, `Portscan.h`)**: Checks a fixed list of 28 common TCP ports (`21` through `27017`) using non-blocking sockets and `poll()` with a `1500 ms` timeout (`SCAN_TIMEOUT_MS`), then reports open/closed/filtered counts.
* **Flow control (`main.c`)**: Parses a single `<hostname or IPV4 address>` argument and runs ping, port scan, or both in sequence.

## Why it isn't ready for real-world use

* **Unfinished & experimental**: Several parts are basic prototypes rather than complete, hardened tooling.
* **Privileges & raw sockets**: Opening `SOCK_RAW` for ICMP typically requires root or `CAP_NET_RAW`.
* **Limited coverage & edge cases**: Port scanning only covers a small hardcoded port table, uses a short fixed timeout (`1500 ms`), doesn't do service/banner fingerprinting, and can misclassify slow or rate-limited responses as filtered.
* **Not audited for production**: Error handling, signal/state edge cases, and network noise/rate-limiting haven't been battle-tested against real-world targets.

### Clone the repository

```bash
git clone [https://github.com/Yared-Cyber/Panda.git](https://github.com/Yared-Cyber/Panda.git)
cd Panda
``` 

## Building & running (Linux)

You'll need a C compiler (`gcc` or `clang`) and POSIX/Linux headers.

```bash
gcc -Wall -Wextra -Iinclude src/main.c src/scanner.c src/Portscan.c src/tui.c -o Panda
sudo ./Panda <hostname-or-ipv4>
```
https://github.com/user-attachments/assets/05edef21-94cb-42ce-906f-522a1a91a00d
