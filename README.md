# 9M2PJU-ESP32-C3-AdBlocker

A **Pi-hole-style DNS ad-blocker** that runs on a **$2 ESP32-C3** — *no PSRAM required*.

The trick everyone misses: you don't need to keep the blocklist in RAM. Store the
domains as **sorted 40-bit hashes in flash** and binary-search them. 140,000+ domains
fit in ~0.7 MB of flash and are matched in **<1 ms** (with Bloom filter pre-filter),
using **~180 KB of RAM** (including the 128 KB Bloom filter).

## What's new in this version

This is a heavily upgraded fork of the original `esp32-c3-adblock`. Every item from
the original "how it could grow" list is done, plus a long list of correctness,
performance, and security fixes:

### Performance
- **Bloom filter in RAM** (128 KB) — skips flash for ~93% of non-blocked queries.
  Average lookup is now **0 flash reads** instead of ~18.
- **Async upstream forwarding** — up to 32 concurrent queries instead of blocking
  on one upstream reply at a time. No more "one slow query freezes the sinkhole."
- **Custom domains sorted + binary-searched** (was a linear scan of up to 200).
- **Removed `delay(1)` from the main loop** — was capping throughput at ~1000 it/s.
- **`isBlocked` uses `memchr` + length tracking** instead of `strlen` per suffix.

### Correctness
- **AAAA sinkhole** — blocked IPv6 queries now answer `::` instead of leaking
  upstream. Was: only A records were sinkholed, AAAA bypassed the blocklist.
- **TCP DNS on port 53** — handles truncated-response / DNSSEC fallback. Was UDP-only.
- **1232-byte DNS buffer** (RFC 6891 max UDP) — was 600, large replies were truncated.
- **Client table with LRU eviction** — was silently dropping stats past 96 clients.
- **Banned IPs decoupled from the client table** — banning an IP with no active
  client entry now persists correctly.
- **Idle-gated remote blocklist fetch** — only runs when DNS has been quiet 3+ s,
  so a 20-second HTTPS download no longer freezes the household's DNS.
- **`millis()` wraparound-safe timing** — was broken every ~49 days of uptime.
- **`parseQuery` robust bounds checking** — was fragile on compression pointers.

### Security
- **Dashboard authentication** — Basic Auth with a random password generated on
  first boot (printed on serial). Was: no auth, anyone on the LAN could flash
  firmware or swap the blocklist.
- **CSRF token** on all mutating endpoints — a malicious page on the LAN can't
  ban clients or upload firmware via the victim's browser.
- **CA-verified HTTPS** for remote blocklist fetches — was `setInsecure()`, which
  let a MITM swap your blocklist for an empty one (silently disabling blocking).

### Features
- **WiFiManager captive portal** — first-boot WiFi setup without recompiling.
  Connect to the `C3AdBlock-Setup` AP, enter creds at `http://192.168.4.1`, done.
  WiFi can also be changed later from the dashboard.
- **Optional DHCP server** — the C3 can hand itself out as DNS for true
  plug-and-play. Toggle from the dashboard (disable your router's DHCP first).
- **Blocklist v1 binary format** with header (magic `CADB` + version + hash_bytes)
  — the firmware validates on load, so a `HASH_BYTES` mismatch is rejected instead
  of silently corrupting lookups.
- **Collision report** — `build_blocklist.py` writes `blocklist.bin.collisions.txt`
  listing any domain pairs sharing a 40-bit hash, so the operator can decide.
- **ETag + Cache-Control** on the dashboard HTML — the 6 KB page is served with a
  304 path instead of re-sent on every 3-second poll.
- **WiFi change from the dashboard** — no reflash needed to switch networks.

### Code quality
- **Dashboard HTML extracted** to `src/dashboard_html.h` (was inline in `main.cpp`).
- **33 Python tests** for hashing, normalization, binary format, and Bloom filter
  correctness (`python3 tools/test_build_blocklist.py`).
- **`LOG`/`LOGN` macros** — silence serial output with `-DNDEBUG`.
- **Removed hardcoded `/dev/ttyACM0`** from `platformio.ini` — PlatformIO
  auto-detects the port.
- **Removed dead `Dev.label` field** that was never set anywhere.

### Build footprint
| | original | this version |
|---|---|---|
| RAM | 54 KB | 56 KB (+2 KB for async pending table) |
| Flash | 1018 KB | 1032 KB (+14 KB for TCP DNS, DHCP, auth, captive portal, Bloom loader) |
| Lookups | ~18 flash reads/query | **0 flash reads** for 93% of queries |
| Concurrent upstream queries | 1 | **32** |


```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ Bloom filter check (RAM, ~0.5 µs)
              ├─ miss ──▶ forward to upstream (async, non-blocking)
              └─ hit  ──▶ binary-search the flash hash table
                          ├─ hit  ──▶ answer 0.0.0.0 / ::  (sinkholed)
                          └─ miss ──▶ forward to upstream (async, non-blocking)
```

## Why this is interesting

Most ESP32 DNS sinkholes load the blocklist (domain *strings*) into RAM, so they
demand PSRAM. This project stores fixed **5-byte (40-bit) hashes in flash** instead,
with a **Bloom filter in RAM** as a fast pre-filter:

| | string-in-RAM approach | this (hash-in-flash + bloom) |
|---|---|---|
| Hardware | ESP32 + PSRAM (~$8) | ESP32-C3, no PSRAM (~$2) |
| 141k domains | ~2.5 MB of RAM | **0.67 MB of flash + 128 KB bloom** |
| RAM used | most of it | **~180 KB** (bloom + stack) |
| Lookup | string compare | **0 flash reads** for 93% of misses (bloom) |
| Collisions | n/a | 0 at 141k (1 at 537k) |
| Upstream | blocking (1 query at a time) | **async (32 concurrent)** |

**Why 40 bits?** It's the sweet spot for this flash budget. Collisions follow the
birthday bound — at 141k domains you get ~0, at 537k about 1 (i.e. one unlucky
domain gets over-blocked). Dropping to 32 bits would save 20% of the flash but
cost ~7 collisions at 250k; going to 64 bits wastes 3 bytes per domain to solve
a problem you don't have.

**Why a Bloom filter?** ~93% of DNS queries are for domains *not* in the blocklist.
The Bloom filter (128 KB of RAM) eliminates flash access for those — only the ~7%
that pass the bloom check do the ~18-flash-read binary search. Net result: the
average query does **0 flash reads**, not 18.

The same trick works on bigger chips — it isn't a C3 workaround. On a 16 MB
ESP32-S3 these hashes hold **~2.7M domains** vs ~466k for strings in 8 MB of
PSRAM. Hashes in flash beat strings in PSRAM basically everywhere; the C3 just
makes it undeniable.

## Hardware

- Any **ESP32-C3** board (tested on a C3 SuperMini), 4 MB flash, **no PSRAM needed**
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.
- A **USB-A → USB-C dongle** lets it plug straight into the spare USB port on the
  back of most routers — no power supply, no extra box.

### Enclosure

A printable case for the C3 SuperMini: [`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

Printing notes:
- No supports needed; 0.2 mm layers, ~15% infill is plenty.
- **Keep the antenna end clear.** The C3's PCB antenna is the zig-zag trace on the
  short edge opposite the USB-C port — don't bury it in solid plastic or put metal
  near it, or your RSSI will suffer.
- Leave the vents open: the board idles around 45–55 °C.

## Build & flash (PlatformIO)

One USB flash to get going — after that, **firmware and blocklist both update over WiFi** (see below).

```bash
# 1. (optional) set WiFi creds via secrets.h — or skip and use the captive portal
cp src/secrets.example.h src/secrets.h
#    then edit src/secrets.h -> WIFI_SSID / WIFI_PASS
#    (if you skip this, the device starts a setup AP on first boot)

# 2. build the blocklist hash table (default = StevenBlack base + Hagezi Light,
#    ~140k domains, WhatsApp/social safe)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. flash firmware + the blocklist filesystem (the one and only USB flash)
pio run -t upload
pio run -t uploadfs

# 4. watch it boot, note the IP / auth password / open the dashboard
pio device monitor          # -> http://c3adblock.local
```

### First-boot WiFi setup (captive portal)

If you don't create `secrets.h` (or the credentials are wrong), the device starts
an AP called **C3AdBlock-Setup**. Connect to it and open
**http://192.168.4.1** to enter your WiFi credentials. The device saves them,
reboots, and joins your network. You can change WiFi later from the dashboard.

### Dashboard authentication

On first boot, a random password is generated and saved to flash. It's printed
on the serial console:

```
[cfg] dashboard password: xY7kPm2nQa
```

Open `http://c3adblock.local` in a browser — you'll get a Basic Auth prompt.
Enter any username and that password. All mutating actions (ban, add domain,
upload, firmware OTA) also require a CSRF token that's embedded in the dashboard
page, so a malicious site on your LAN can't CSRF your ad-blocker.

## Over-the-air updates (no more USB)

The dashboard at **http://c3adblock.local** does it all:

- **Blocklist** — drop a freshly built `blocklist.bin` into *Blocklist → Upload*, or set a
  URL under *Remote auto-update* and the device pulls a prebuilt `blocklist.bin`
  on a schedule (e.g. a GitHub release asset — update it once, every device fetches it).
  Remote fetches use **CA-verified HTTPS** (no `setInsecure`) and only run when DNS
  has been idle for 3+ seconds, so they don't interrupt service.
- **Firmware** — upload `.pio/build/c3/firmware.bin` under *Firmware → OTA update*; the
  device verifies it and reboots into the new image. Or push over WiFi from the CLI:
  ```bash
  pio run -t upload --upload-port c3adblock.local --upload-protocol espota
  ```
- **WiFi** — change the WiFi network from the dashboard (no reflash needed).
- **DHCP** — optionally enable the built-in DHCP server so the C3 hands itself out
  as the DNS server. Disable your router's DHCP first, then toggle this on.

**4 MB flash tradeoff:** firmware OTA needs *two* app slots, which leaves ~1.3 MB for the
blocklist (**~250k domains max**). The aggressive 537k "ultimate" list only fits the
single-app partition table (no firmware OTA). Pick your tradeoff in `partitions.csv`.

## Use it

Point a device's DNS at the C3's IP, or add it as a **secondary resolver** behind
your main DNS. For true plug-and-play, enable the **DHCP server** from the dashboard
(disable your router's DHCP first). Test:

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  (blocked, A)
dig @<c3-ip> doubleclick.net AAAA  # -> ::  (blocked, AAAA — no IPv6 leak)
dig @<c3-ip> github.com        # -> real IP  (forwarded)
```

## How domain matching works

The `isBlocked` function walks **parent suffixes** of the queried domain. For a
query like `ads.server.example.com`, it checks (in order):

1. `ads.server.example.com`
2. `server.example.com`
3. `example.com`

It **stops before the bare TLD** (`com`) — a block on `com` would break the entire
TLD and is never tested. This means you can block `doubleclick.net` and all
subdomains (`ad.doubleclick.net`, `stat.doubleclick.net`, ...) are caught
automatically.

Each suffix is FNV-1a hashed (40-bit truncated), checked against the RAM Bloom
filter first, and only on a Bloom hit is the flash hash table binary-searched.
Custom domains (added via the dashboard) are kept in a separate sorted array and
binary-searched too.

## Blocklist binary format (v1)

```
Header (20 bytes):
  [0..3]   magic 'CADB'
  [4]      version (1)
  [5]      hash_bytes (5)
  [6..9]   num_hashes (uint32 LE)
  [10..13] bloom_bits (uint32 LE)
  [14]     bloom_k (uint8)
  [15..19] reserved

Bloom filter: ceil(bloom_bits / 8) bytes
Hash table:   num_hashes * 5 bytes (sorted, little-endian)
```

The firmware validates the magic, version, and hash_bytes on load — a mismatch
(e.g. wrong `HASH_BYTES`) is rejected instead of silently corrupting lookups.
Collisions are reported to `blocklist.bin.collisions.txt` by the build script.

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which **resets the C3** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The C3's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## Testing

```bash
python3 tools/test_build_blocklist.py    # 33 tests: hashing, normalization, binary format, bloom
```

## Done / how it could grow

- ✅ Web dashboard — per-client block/allow counts, ban a client, add custom domains
- ✅ mDNS (`c3adblock.local`) for discovery
- ✅ OTA — firmware + blocklist update over WiFi, plus scheduled remote blocklist pulls
- ✅ Bloom filter in RAM as a fast pre-filter (skip flash for ~93% of misses)
- ✅ Async upstream forwarding (32 concurrent queries, no blocking)
- ✅ TCP DNS support (port 53)
- ✅ AAAA sinkhole (blocked IPv6 queries answered with `::`, not leaked upstream)
- ✅ Dashboard auth (Basic Auth + CSRF token)
- ✅ WiFiManager captive portal (first-boot WiFi setup without recompiling)
- ✅ Optional DHCP server (hands out C3 as DNS for plug-and-play)
- ✅ CA-verified HTTPS for remote blocklist fetches
- ✅ Blocklist v1 format with header validation
- ⬜ Per-client blocking rules (different blocklists for different devices)
- ⬜ Allowlist (override blocklist for specific domains)
- ⬜ Query logging / export

## Credits

Inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the
"answer 0.0.0.0 for blocklisted domains" idea. This is an independent from-scratch
implementation focused on the hash-in-flash optimization for PSRAM-less chips.

## License

MIT — see [LICENSE](LICENSE).
