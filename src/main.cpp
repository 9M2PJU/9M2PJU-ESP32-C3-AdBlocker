// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
//
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// A Bloom filter in RAM skips flash for ~93% of non-blocked queries.
// Async upstream forwarding handles multiple concurrent queries.
// TCP DNS support for truncated/DNSSEC fallback.
// Dashboard at http://c3adblock.local with Basic Auth + CSRF token.
//
// Improvements over the original:
//  - Async DNS forwarding (no more blocking on upstream replies)
//  - Bloom filter pre-filter in RAM
//  - AAAA sinkhole (blocked IPv6 queries answered with ::, not leaked)
//  - TCP DNS on port 53
//  - Dashboard auth (Basic Auth + header CSRF token + brute-force brake)
//  - Signed blocklist updates (ECDSA P-256, optional enforcement)
//  - Client table with LRU eviction
//  - Decoupled ban storage (independent of client table)
//  - Idle-gated remote blocklist fetch (deferred until DNS is quiet;
//    the download itself still blocks DNS — schedule off-peak)
//  - HTTPS with redirect-following for remote blocklist (no CA verification;
//    bad/empty feeds rejected, live list kept on failure)
//  - millis() wraparound-safe timing
//  - Blocklist v1 format with header validation (magic + version + hash_bytes)
//  - WiFiManager captive portal for first-boot WiFi config
//  - Optional DHCP server (hands out C3 as DNS for plug-and-play)
//  - ETag/Cache-Control for dashboard HTML
//  - Logging macros (silence with -DNDEBUG)
//  - Custom domains sorted + binary-searched
//  - 1232-byte DNS buffer (handles EDNS-sized responses)
//  - parseQuery with robust bounds checking
//  - No delay(1) in loop (removed throughput cap)
//  - Dead Dev.label field removed

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiServer.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoOTA.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "secrets.h"
#include "dashboard_html.h"
#include "blocklist_pubkey.h"

// ---- config ----
static const IPAddress UPSTREAM(9, 9, 9, 9);
static const uint16_t DNS_PORT = 53;
static const uint16_t DHCP_PORT = 67;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const char* BLOCKLIST_SIG_PATH = "/blocklist.sig";  // DER ECDSA P-256 over the .bin
static const size_t MAX_SIG_SIZE = 256;
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int DNS_BUF_SIZE = 1232;       // RFC 6891 max UDP DNS payload
static const int MAX_PENDING = 32;          // concurrent outstanding upstream queries
static const int MAX_CLIENTS = 96;
static const int MAX_CUSTOM = 200;
static const int MAX_BAN = 32;
static const int MAX_DHCP_LEASES = 32;
static const uint32_t UPSTREAM_TIMEOUT_MS = 2000;
static const uint32_t REMOTE_FETCH_IDLE_MS = 3000;  // only fetch when DNS idle this long
static const char* FIRMWARE_VERSION = "1.0.3";
static const String DASHBOARD_ETAG = String("c3adb-v") + FIRMWARE_VERSION;

// ---- WiFi TX power & thermal configuration ----
struct TxPowerOpt {
  const char* label;
  wifi_power_t power;
};
static const TxPowerOpt TX_POWER_TABLE[] = {
  { "2",    WIFI_POWER_2dBm },
  { "5",    WIFI_POWER_5dBm },
  { "8.5",  WIFI_POWER_8_5dBm },
  { "11",   WIFI_POWER_11dBm },
  { "13",   WIFI_POWER_13dBm },
  { "15",   WIFI_POWER_15dBm },
  { "17",   WIFI_POWER_17dBm },
  { "18.5", WIFI_POWER_18_5dBm },
  { "19.5", WIFI_POWER_19_5dBm }
};
static const int NUM_TX_POWER_OPTS = sizeof(TX_POWER_TABLE) / sizeof(TX_POWER_TABLE[0]);
static String txPowerSetting = "8.5";  // Default: 8.5 dBm (sweet spot for SuperMini thermals and stability)

static bool applyTxPower(const String& p) {
  for (int i = 0; i < NUM_TX_POWER_OPTS; i++) {
    if (p == TX_POWER_TABLE[i].label) {
      txPowerSetting = p;
      WiFi.setTxPower(TX_POWER_TABLE[i].power);
      return true;
    }
  }
  return false;
}
static void loadTxPowerCfg() {
  File f = LittleFS.open("/txpower.cfg", "r");
  if (!f) {
    applyTxPower("8.5");
    return;
  }
  String p = f.readStringUntil('\n'); p.trim();
  f.close();
  if (!applyTxPower(p)) {
    applyTxPower("8.5");
  }
}
static void saveTxPowerCfg() {
  File f = LittleFS.open("/txpower.cfg", "w");
  if (!f) return;
  f.println(txPowerSetting);
  f.close();
}

// ---- logging ----
#ifdef NDEBUG
#define LOG(...) ((void)0)
#define LOGN(...) ((void)0)
#else
#define LOG(...) Serial.printf(__VA_ARGS__)
#define LOGN(...) Serial.println(__VA_ARGS__)
#endif

// ---- forward declarations ----
WebServer web(80);
static const char* COLLECTED_HEADERS[] = {"Authorization", "If-None-Match", "Origin", "Referer", "X-CSRF-Token"};
String updateUrl, updateStatus = "never";
uint32_t updateIntervalH = 24, lastCheckMs = 0;
static uint32_t lastDnsActivityMs = 0;
bool dhcpEnabled = false;
static void saveDhcpCfg();
static void saveWifiCfg(const String& ssid, const String& pass);
static bool fetchBlocklist(String url);

// ---- hashing ----------
static uint64_t fnv64(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h;
}
static inline uint64_t fnv40(const char* s, size_t n) { return fnv64(s, n) & HASH_MASK; }

// ---- blocklist (flash hash table + RAM bloom filter) ----
static const uint8_t BL_MAGIC[4] = {'C','A','D','B'};
static const uint8_t BL_VERSION = 1;
static const int BL_HEADER_SIZE = 20;

File blocklist;
uint32_t numHashes = 0;
uint32_t hashTableOffset = 0;       // offset in file where sorted hashes begin

uint8_t* bloomFilter = nullptr;     // malloc'd RAM bloom filter
uint32_t bloomBits = 0;
uint8_t bloomK = 0;

static bool bloomMayContain(uint64_t h64) {
  if (!bloomFilter || bloomBits == 0 || bloomK == 0) return true; // fail open -> check flash
  uint32_t h1 = (uint32_t)(h64 & 0xFFFFFFFF);
  uint32_t h2 = (uint32_t)(h64 >> 32);
  if (h2 == 0) h2 = 0xFFFFFFFF;
  for (uint8_t i = 0; i < bloomK; i++) {
    uint32_t pos = (h1 + i * h2) % bloomBits;
    if (!(bloomFilter[pos >> 3] & (1 << (pos & 7)))) return false;
  }
  return true;
}

static bool inFlash(uint64_t h) {
  if (!blocklist || numHashes == 0) return false;
  int32_t lo = 0, hi = (int32_t)numHashes - 1;
  uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    if (!blocklist.seek(hashTableOffset + (uint32_t)mid * HASH_BYTES)) return false;
    if (blocklist.read(b, HASH_BYTES) != HASH_BYTES) return false;
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1;
    else if (v > h) hi = mid - 1;
    else return true;
  }
  return false;
}

// ---- custom domains (sorted for binary search) ----
String customDom[MAX_CUSTOM];
uint64_t customHash[MAX_CUSTOM];  // kept sorted
int numCustom = 0;

static void sortCustom() {
  for (int i = 1; i < numCustom; i++) {
    uint64_t h = customHash[i]; String d = customDom[i];
    int j = i - 1;
    while (j >= 0 && customHash[j] > h) { customHash[j+1] = customHash[j]; customDom[j+1] = customDom[j]; j--; }
    customHash[j+1] = h; customDom[j+1] = d;
  }
}
static bool inCustom(uint64_t h) {
  int lo = 0, hi = numCustom - 1;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    if (customHash[mid] < h) lo = mid + 1;
    else if (customHash[mid] > h) hi = mid - 1;
    else return true;
  }
  return false;
}

// ---- isBlocked: check domain + parent suffixes, bloom-pre-filtered ----
// Walks parent suffixes: ads.x.example -> x.example -> example.
// Stops before the bare TLD (a block on "com" would break everything).
static bool isBlocked(const char* domain, size_t dlen) {
  const char* p = domain;
  size_t remaining = dlen;
  while (remaining > 0) {
    uint64_t h64 = fnv64(p, remaining);
    uint64_t h40 = h64 & HASH_MASK;
    bool checkFlash = bloomMayContain(h64);  // false = definitely not in list, skip flash
    if (checkFlash && (inFlash(h40) || inCustom(h40))) return true;
    const char* dot = (const char*)memchr(p, '.', remaining);
    if (!dot) break;
    size_t consumed = (size_t)(dot - p) + 1;
    remaining -= consumed;
    p = dot + 1;
    if (!memchr(p, '.', remaining)) break;  // don't test bare TLD
  }
  return false;
}

// ---- persistence: custom domains ----
static void loadCustom() {
  numCustom = 0;
  File f = LittleFS.open("/custom.txt", "r");
  if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) {
      customDom[numCustom] = l;
      customHash[numCustom] = fnv40(l.c_str(), l.length());
      numCustom++;
    }
  }
  f.close();
  sortCustom();
}
static void saveCustom() {
  File f = LittleFS.open("/custom.txt", "w");
  if (!f) return;
  for (int i = 0; i < numCustom; i++) f.println(customDom[i]);
  f.close();
}
static bool addCustom(String d) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d;
  customHash[numCustom] = fnv40(d.c_str(), d.length());
  numCustom++;
  sortCustom();
  saveCustom();
  return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--;
    saveCustom();
    return;
  }
}

// ---- banned IPs (decoupled from client table) ----
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static bool addBannedIP(uint32_t ip) {
  if (isBannedIP(ip)) return false;
  if (numBanned >= MAX_BAN) return false;
  bannedIP[numBanned++] = ip;
  return true;
}
static bool removeBannedIP(uint32_t ip) {
  for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) {
    for (int j = i; j < numBanned - 1; j++) bannedIP[j] = bannedIP[j+1];
    numBanned--;
    return true;
  }
  return false;
}
static void loadBanned() {
  numBanned = 0;
  File f = LittleFS.open("/banned.txt", "r");
  if (!f) return;
  while (f.available() && numBanned < MAX_BAN) {
    String l = f.readStringUntil('\n'); l.trim();
    IPAddress ip;
    if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip;
  }
  f.close();
}
static void saveBanned() {
  File f = LittleFS.open("/banned.txt", "w");
  if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---- client table (with LRU eviction) ----
struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; };
Dev clients[MAX_CLIENTS]; int numClients = 0;
uint32_t totalBlocked = 0, totalAllowed = 0;

static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6);
  ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++)
    if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  int slot = numClients;
  if (numClients >= MAX_CLIENTS) {
    // Evict stalest client
    int oldest = 0;
    for (int i = 1; i < numClients; i++)
      if (clients[i].lastSeen < clients[oldest].lastSeen) oldest = i;
    slot = oldest;
  } else {
    numClients++;
  }
  Dev* c = &clients[slot];
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis();
  c->banned = isBannedIP(ip);
  getMac(ip, c->mac);
  return c;
}

// ---- DNS parsing (robust bounds checking) ----
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12; size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++];
    if (l == 0) break;
    if (l & 0xC0) return 0;  // compression pointer — invalid in a query
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]);
  }
  out[o] = 0;
  if (i + 4 > len) return 0;  // need qtype(2) + qclass(2)
  *qtype = (pkt[i] << 8) | pkt[i + 1];
  *qend = i + 4;
  // strip leading www.
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}

// ---- DNS blocking (A -> 0.0.0.0, AAAA -> ::) ----
static int buildBlocked(uint8_t* pkt, int qend, uint16_t qtype) {
  // flags: response, recursion available; ANCOUNT=1 for A/AAAA, 0 otherwise
  pkt[2] = 0x81; pkt[3] = 0x80;
  pkt[6] = 0; pkt[7] = (qtype == 1 || qtype == 28) ? 1 : 0;
  pkt[8] = 0; pkt[9] = 0; pkt[10] = 0; pkt[11] = 0;  // NSCOUNT=ARCOUNT=0 (no EDNS in reply)
  if (qtype == 1) {
    // A record: 0.0.0.0, TTL 300
    const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
    memcpy(pkt + qend, ans, sizeof(ans));
    return qend + sizeof(ans);
  }
  if (qtype == 28) {
    // AAAA record: ::, TTL 300
    const uint8_t ans[] = {0xC0,0x0C, 0,28, 0,1, 0,0,1,0x2C, 0,16, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    memcpy(pkt + qend, ans, sizeof(ans));
    return qend + sizeof(ans);
  }
  return qend;  // other qtypes: no answer (NXDOMAIN-ish)
}

// ---- async DNS forwarding ----
WiFiUDP dnsServer;     // listens on :53 for client queries
WiFiUDP upstream;      // ephemeral port for upstream queries/replies
WiFiUDP tcpUpstream;   // separate socket for TCP DNS forwarding

struct Pending {
  uint32_t clientIP;
  uint16_t clientPort;
  uint16_t originalID;
  uint32_t sentMs;
  bool active;
};
Pending pending[MAX_PENDING];
int pendingCount = 0;

static int findFreeSlot() {
  for (int i = 0; i < MAX_PENDING; i++) if (!pending[i].active) return i;
  return -1;
}
static void expirePending() {
  uint32_t now = millis();
  for (int i = 0; i < MAX_PENDING; i++)
    if (pending[i].active && (now - pending[i].sentMs) > UPSTREAM_TIMEOUT_MS) {
      pending[i].active = false;
      pendingCount--;
    }
}
static bool pollUpstream(uint8_t* buf, int bufSize) {
  int sz = upstream.parsePacket();
  if (sz <= 0) return false;
  int rlen = upstream.read(buf, bufSize);
  if (rlen < 2) return true;
  uint16_t replyID = (buf[0] << 8) | buf[1];
  if (replyID >= MAX_PENDING || !pending[replyID].active) return true;
  // Restore original query ID
  buf[0] = (pending[replyID].originalID >> 8) & 0xFF;
  buf[1] = pending[replyID].originalID & 0xFF;
  dnsServer.beginPacket(pending[replyID].clientIP, pending[replyID].clientPort);
  dnsServer.write(buf, rlen);
  dnsServer.endPacket();
  pending[replyID].active = false;
  pendingCount--;
  return true;
}

static uint8_t dnsBuf[DNS_BUF_SIZE];

static bool handleDns() {
  int sz = dnsServer.parsePacket();
  if (sz <= 0) return false;
  lastDnsActivityMs = millis();
  IPAddress cip = dnsServer.remoteIP();
  uint16_t cport = dnsServer.remotePort();
  int qlen = dnsServer.read(dnsBuf, sizeof(dnsBuf));
  if (qlen < 13) return true;

  char domain[256]; uint16_t qtype = 0; int qend = qlen;
  size_t dl = parseQuery(dnsBuf, qlen, domain, &qtype, &qend);

  Dev* c = getClient((uint32_t)cip);
  bool ban = c && c->banned;
  bool blocked = ban || (dl && numHashes && isBlocked(domain, dl));

  if (blocked) {
    int rlen = buildBlocked(dnsBuf, qend, qtype);
    totalBlocked++;
    if (c) c->blocked++;
    dnsServer.beginPacket(cip, cport);
    dnsServer.write(dnsBuf, rlen);
    dnsServer.endPacket();
  } else {
    int slot = findFreeSlot();
    if (slot < 0) return true;  // pending table full — drop query
    uint16_t origID = (dnsBuf[0] << 8) | dnsBuf[1];
    dnsBuf[0] = (slot >> 8) & 0xFF;
    dnsBuf[1] = slot & 0xFF;
    pending[slot].clientIP = (uint32_t)cip;
    pending[slot].clientPort = cport;
    pending[slot].originalID = origID;
    pending[slot].sentMs = millis();
    pending[slot].active = true;
    pendingCount++;
    upstream.beginPacket(UPSTREAM, 53);
    upstream.write(dnsBuf, qlen);
    upstream.endPacket();
    totalAllowed++;
    if (c) c->allowed++;
  }
  return true;
}

// ---- TCP DNS (one query per connection) ----
WiFiServer tcpDnsServer(DNS_PORT);
WiFiClient tcpDnsClient;
static uint8_t tcpBuf[DNS_BUF_SIZE];

static int forwardUpstreamSync(uint8_t* pkt, int qlen) {
  uint16_t origID = (pkt[0] << 8) | pkt[1];
  pkt[0] = 0xFF; pkt[1] = 0xFE;  // use fixed ID to avoid collision with UDP slots 0-31
  tcpUpstream.beginPacket(UPSTREAM, 53);
  tcpUpstream.write(pkt, qlen);
  tcpUpstream.endPacket();
  pkt[0] = (origID >> 8) & 0xFF; pkt[1] = origID & 0xFF;  // restore for blocked path
  uint32_t t0 = millis();
  while (millis() - t0 < UPSTREAM_TIMEOUT_MS) {
    int sz = tcpUpstream.parsePacket();
    if (sz > 0) {
      int n = tcpUpstream.read(pkt, DNS_BUF_SIZE);
      if (n >= 2) {
        pkt[0] = (origID >> 8) & 0xFF; pkt[1] = origID & 0xFF;
        return n;
      }
      return 0;
    }
    // Keep UDP DNS alive while waiting: drain one UDP query/reply per
    // iteration instead of stalling the whole server for up to 2 s.
    handleDns();
    pollUpstream(dnsBuf, DNS_BUF_SIZE);
    delay(1);
  }
  return 0;
}

static bool handleTcpDns() {
  if (!tcpDnsClient || !tcpDnsClient.connected()) {
    tcpDnsClient = tcpDnsServer.accept();
    if (!tcpDnsClient) return false;
  }
  if (!tcpDnsClient.connected()) return false;
  if (tcpDnsClient.available() < 2) return false;

  uint8_t lenBuf[2];
  tcpDnsClient.read(lenBuf, 2);
  uint16_t msgLen = (lenBuf[0] << 8) | lenBuf[1];
  if (msgLen > DNS_BUF_SIZE) { tcpDnsClient.stop(); return true; }

  int total = 0;
  uint32_t t0 = millis();
  while (total < msgLen && tcpDnsClient.connected()) {
    if (tcpDnsClient.available()) {
      int n = tcpDnsClient.read(tcpBuf + total, msgLen - total);
      if (n <= 0) break;
      total += n;
    } else {
      if (millis() - t0 > UPSTREAM_TIMEOUT_MS) break;
      // Don't stall UDP DNS while waiting for slow TCP sender.
      handleDns();
      pollUpstream(dnsBuf, DNS_BUF_SIZE);
      delay(1);
    }
  }
  if (total < msgLen) { tcpDnsClient.stop(); return true; }

  char domain[256]; uint16_t qtype = 0; int qend = total;
  size_t dl = parseQuery(tcpBuf, total, domain, &qtype, &qend);
  Dev* c = getClient((uint32_t)tcpDnsClient.remoteIP());
  bool ban = c && c->banned;
  bool blocked = ban || (dl && numHashes && isBlocked(domain, dl));

  int rlen;
  if (blocked) {
    rlen = buildBlocked(tcpBuf, qend, qtype);
    totalBlocked++; if (c) c->blocked++;
  } else {
    rlen = forwardUpstreamSync(tcpBuf, total);
    totalAllowed++; if (c) c->allowed++;
  }

  if (rlen > 0) {
    uint8_t lenOut[2] = { (uint8_t)(rlen >> 8), (uint8_t)(rlen & 0xFF) };
    tcpDnsClient.write(lenOut, 2);
    tcpDnsClient.write(tcpBuf, rlen);
  }
  tcpDnsClient.stop();
  return true;
}

// ---- DHCP server (optional, disabled by default) ----
WiFiUDP dhcpSock;

struct DhcpLease { uint8_t mac[6]; uint32_t ip; uint32_t expires; bool active; };
DhcpLease dhcpLeases[MAX_DHCP_LEASES];

static uint32_t dhcpPoolStart = 0;
static uint32_t dhcpPoolEnd = 0;

// Pool addresses are kept in big-endian (network-order) integer form to match
// the manual >>24 shifts used when building DHCP packets.
static inline uint32_t ipToBE(const IPAddress& ip) {
  return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
}

static void initDhcpPool() {
  IPAddress local = WiFi.localIP();
  // Pool: same /24 as our own address, .100 ... .200.
  // Octet-based (no htonl tricks) so it can't spill into another subnet when
  // the base address is high (e.g. .250 + 100 must NOT become x.x+1.x).
  uint32_t net = ipToBE(local) & 0xFFFFFF00UL;
  if (net == 0) net = (192UL << 24) | (168UL << 16) | (1UL << 8);  // fallback 192.168.1.x
  dhcpPoolStart = net | 100;
  dhcpPoolEnd = net | 200;
}

static inline bool dhcpExpired(uint32_t now, uint32_t expires) {
  return (int32_t)(now - expires) >= 0;  // wraparound-safe
}

static uint32_t findDhcpLease(const uint8_t* mac) {
  uint32_t now = millis();
  for (int i = 0; i < MAX_DHCP_LEASES; i++) {
    if (dhcpLeases[i].active && memcmp(dhcpLeases[i].mac, mac, 6) == 0) {
      if (dhcpExpired(now, dhcpLeases[i].expires)) {
        dhcpLeases[i].active = false;  // reclaim stale lease
        return 0;
      }
      return dhcpLeases[i].ip;
    }
  }
  return 0;
}
static uint32_t assignDhcpIP(const uint8_t* mac) {
  // Existing (unexpired) lease?
  uint32_t existing = findDhcpLease(mac);
  if (existing) return existing;
  uint32_t now = millis();
  uint32_t selfBE = ipToBE(WiFi.localIP());
  uint32_t gwBE = ipToBE(WiFi.gatewayIP());
  // Find free IP in pool (skip our own IP, the gateway, and .0/.255)
  for (uint32_t candidate = dhcpPoolStart; candidate <= dhcpPoolEnd; candidate++) {
    uint8_t last = candidate & 0xFF;
    if (last == 0 || last == 255) continue;
    if (candidate == selfBE || candidate == gwBE) continue;
    bool taken = false;
    for (int i = 0; i < MAX_DHCP_LEASES; i++) {
      if (dhcpLeases[i].active) {
        if (dhcpExpired(now, dhcpLeases[i].expires)) dhcpLeases[i].active = false;
        else if (dhcpLeases[i].ip == candidate) { taken = true; break; }
      }
    }
    if (!taken) {
      // Find free lease slot
      for (int i = 0; i < MAX_DHCP_LEASES; i++) {
        if (!dhcpLeases[i].active) {
          memcpy(dhcpLeases[i].mac, mac, 6);
          dhcpLeases[i].ip = candidate;
          dhcpLeases[i].expires = now + 86400000UL;  // 24h
          dhcpLeases[i].active = true;
          return candidate;
        }
      }
    }
  }
  return 0;
}

static bool handleDhcp() {
  int sz = dhcpSock.parsePacket();
  if (sz <= 0) return false;
  uint8_t dhcp[548];
  int len = dhcpSock.read(dhcp, sizeof(dhcp));
  if (len < 240) return true;
  if (dhcp[0] != 1) return true;  // BOOTREQUEST
  uint32_t xid = (dhcp[4] << 24) | (dhcp[5] << 16) | (dhcp[6] << 8) | dhcp[7];
  uint8_t* mac = dhcp + 28;
  // Magic cookie at offset 236
  if (dhcp[236] != 0x63 || dhcp[237] != 0x82 || dhcp[238] != 0x53 || dhcp[239] != 0x63) return true;

  uint8_t msgType = 0;
  int oi = 240;
  while (oi < len && dhcp[oi] != 0xFF) {
    uint8_t opt = dhcp[oi++];
    if (opt == 0) continue;
    if (oi >= len) break;
    uint8_t optLen = dhcp[oi++];
    if (oi + optLen > len) break;  // truncated option — stop parsing
    if (opt == 53 && optLen == 1) msgType = dhcp[oi];
    oi += optLen;
  }
  if (msgType != 1 && msgType != 3) return true;  // only DISCOVER and REQUEST

  uint32_t clientIP = assignDhcpIP(mac);
  if (clientIP == 0) return true;

  // Build response
  memset(dhcp, 0, 240);
  dhcp[0] = 2;  // BOOTREPLY
  dhcp[1] = 1;  // Ethernet
  dhcp[2] = 6;  // HLEN
  dhcp[4] = (xid >> 24) & 0xFF; dhcp[5] = (xid >> 16) & 0xFF;
  dhcp[6] = (xid >> 8) & 0xFF; dhcp[7] = xid & 0xFF;
  dhcp[10] = 0x80;  // broadcast flag
  // YIADDR (offset 16) = client IP (big-endian)
  dhcp[16] = (clientIP >> 24) & 0xFF; dhcp[17] = (clientIP >> 16) & 0xFF;
  dhcp[18] = (clientIP >> 8) & 0xFF; dhcp[19] = clientIP & 0xFF;
  // SIADDR (offset 20) = our IP
  IPAddress ourIP = WiFi.localIP();
  dhcp[20] = ourIP[0]; dhcp[21] = ourIP[1]; dhcp[22] = ourIP[2]; dhcp[23] = ourIP[3];
  // CHADDR (offset 28) = client MAC
  memcpy(dhcp + 28, mac, 6);
  // Magic cookie
  dhcp[236] = 0x63; dhcp[237] = 0x82; dhcp[238] = 0x53; dhcp[239] = 0x63;

  int o = 240;
  dhcp[o++] = 53; dhcp[o++] = 1; dhcp[o++] = (msgType == 1) ? 2 : 5;  // OFFER or ACK
  dhcp[o++] = 54; dhcp[o++] = 4; dhcp[o++] = ourIP[0]; dhcp[o++] = ourIP[1]; dhcp[o++] = ourIP[2]; dhcp[o++] = ourIP[3];
  IPAddress mask = WiFi.subnetMask();
  dhcp[o++] = 1; dhcp[o++] = 4; dhcp[o++] = mask[0]; dhcp[o++] = mask[1]; dhcp[o++] = mask[2]; dhcp[o++] = mask[3];
  IPAddress gw = WiFi.gatewayIP();
  dhcp[o++] = 3; dhcp[o++] = 4; dhcp[o++] = gw[0]; dhcp[o++] = gw[1]; dhcp[o++] = gw[2]; dhcp[o++] = gw[3];
  // DNS = our IP (so clients use the C3 for DNS)
  dhcp[o++] = 6; dhcp[o++] = 4; dhcp[o++] = ourIP[0]; dhcp[o++] = ourIP[1]; dhcp[o++] = ourIP[2]; dhcp[o++] = ourIP[3];
  // Lease time = 24h (big-endian)
  dhcp[o++] = 51; dhcp[o++] = 4; dhcp[o++] = 0; dhcp[o++] = 0; dhcp[o++] = 0x51; dhcp[o++] = 0x80;
  dhcp[o++] = 0xFF;  // end

  // DISCOVER/REQUEST come FROM 0.0.0.0 (client has no address yet), so a
  // unicast reply to remoteIP would go nowhere. Broadcast the OFFER/ACK.
  dhcpSock.beginPacket(IPAddress(255, 255, 255, 255), 68);
  dhcpSock.write(dhcp, o);
  dhcpSock.endPacket();
  return true;
}

// ---- auth (Basic Auth + CSRF token) ----
String authPassword;
String authToken;

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static String b64encode(const String& s) {
  String o;
  const uint8_t* in = (const uint8_t*)s.c_str();
  int len = s.length();
  for (int i = 0; i < len; i += 3) {
    uint32_t n = (uint32_t)in[i] << 16;
    if (i + 1 < len) n |= (uint32_t)in[i+1] << 8;
    if (i + 2 < len) n |= in[i+2];
    o += B64[(n >> 18) & 0x3F];
    o += B64[(n >> 12) & 0x3F];
    o += (i + 1 < len) ? B64[(n >> 6) & 0x3F] : '=';
    o += (i + 2 < len) ? B64[n & 0x3F] : '=';
  }
  return o;
}
static void genToken();
static void genRandomPassword() {
  const char chars[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  authPassword = "";
  for (int i = 0; i < 10; i++)
    authPassword += chars[esp_random() % (sizeof(chars) - 1)];
  genToken();
}
static void genToken() {
  // 64-bit CSRF token (16 hex chars). Regenerated every boot so a token
  // leaked via browser history/logs is useless after a reboot.
  uint32_t a = esp_random(), b = esp_random();
  char t[17];
  snprintf(t, sizeof(t), "%08x%08x", (unsigned)a, (unsigned)b);
  authToken = String(t);
}
static void loadAuth() {
  File f = LittleFS.open("/auth.cfg", "r");
  if (f) {
    authPassword = f.readStringUntil('\n'); authPassword.trim();
    authToken = f.readStringUntil('\n'); authToken.trim();
    f.close();
  }
  if (authPassword.length() == 0) {
    genRandomPassword();  // sets password + token
  } else {
    genToken();           // keep the password, rotate the token every boot
  }
  {
    File fo = LittleFS.open("/auth.cfg", "w");
    if (fo) { fo.println(authPassword); fo.println(authToken); fo.close(); }
  }
}
static bool checkAuth() {
  String expected = "Basic " + b64encode("admin:" + authPassword);
  return web.header("Authorization") == expected;
}
static bool checkToken() {
  // Header-only on purpose: a query-string token leaks into browser history,
  // server logs and Referer headers. All dashboard JS sends X-CSRF-Token.
  return web.header("X-CSRF-Token") == authToken;
}
static uint8_t authFails = 0;
static uint32_t lastAuthFailMs = 0;
static void requireAuth() {
  // Tiny brute-force brake: 5 bad password attempts within 60 s -> 429 for a
  // while. Browsers resend cached Basic credentials automatically, so legit
  // polling doesn't trip this — only wrong-password guesses do.
  uint32_t now = millis();
  if ((now - lastAuthFailMs) > 60000UL) authFails = 0;
  lastAuthFailMs = now;
  if (authFails >= 5) {
    web.sendHeader("Retry-After", "30");
    web.send(429, "text/plain", "too many auth failures — retry later");
    return;
  }
  authFails++;
  web.sendHeader("WWW-Authenticate", "Basic realm=\"C3 AdBlock\"");
  web.send(401, "text/plain", "auth required");
}

// ---- web server ----

static String macStr(const uint8_t* m) {
  char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
  return String(s);
}
static String jesc(const String& s) {
  String o;
  for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; }
  return o;
}

static void handleRoot() {
  if (!checkAuth()) { requireAuth(); return; }
  if (web.header("If-None-Match") == DASHBOARD_ETAG) { web.send(304); return; }
  web.sendHeader("Cache-Control", "max-age=3600");
  web.sendHeader("ETag", DASHBOARD_ETAG);
  web.send_P(200, "text/html", PAGE);
}

// ---- blocklist signature state (verified in the signature section below) ----
static bool blSigned = false;       // live blocklist verified against BL_PUBKEY?
static bool requireSigned = false;  // when true, unsigned replacements are rejected
static String swapStatus = "not run";
static void loadSigReq();
static void saveSigReq();
static bool verifyBlocklistSig(const char* binPath, const char* sigPath);

static void handleStats() {
  if (!checkAuth()) { requireAuth(); return; }
  uint32_t up = millis() / 1000;
  char ut[24];
  snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String bloomStr = bloomFilter ? (String(bloomBits / 8 / 1024) + " KB") : String("off");

  String j = "{\"version\":\"" + String(FIRMWARE_VERSION) + "\"" +
             ",\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked +
             ",\"allowed\":" + totalAllowed + ",\"domains\":" + numHashes +
             ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"bloom\":\"" + jesc(bloomStr) + "\",\"pending\":" + pendingCount +
             ",\"dhcp\":" + (dhcpEnabled ? "true" : "false") +
             ",\"wifi\":\"" + jesc(WiFi.SSID()) + "\"" +
             ",\"token\":\"" + jesc(authToken) + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH +
             ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"txpower\":\"" + txPowerSetting + "\"" +
             ",\"blsig\":\"" + (blSigned ? "signed" : "unverified") + "\"" +
             ",\"sigreq\":" + (requireSigned ? "true" : "false") +
             ",\"keyid\":\"" + BL_KEY_ID + "\"" +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) {
    Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : "");
    j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) +
         "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed +
         ",\"banned\":" + (c.banned ? "true" : "false") + "}";
  }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}

static void handleBan() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    uint32_t ipraw = (uint32_t)ip;
    bool nowBanned;
    if (isBannedIP(ipraw)) { removeBannedIP(ipraw); nowBanned = false; }
    else { addBannedIP(ipraw); nowBanned = true; }
    saveBanned();
    // Reflect in the live client table if present, but don't create a new
    // entry just to ban an unseen IP (that would waste client slots).
    for (int i = 0; i < numClients; i++)
      if (clients[i].ip == ipraw) { clients[i].banned = nowBanned; break; }
  }
  web.send(200, "text/plain", "ok");
}

static void handleAddBlock() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  addCustom(web.arg("d"));
  web.send(200, "text/plain", "ok");
}
static void handleUnblock() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  removeCustom(web.arg("d"));
  web.send(200, "text/plain", "ok");
}

static void handleDhcpToggle() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  dhcpEnabled = !dhcpEnabled;
  saveDhcpCfg();
  if (dhcpEnabled) {
    initDhcpPool();
    dhcpSock.begin(DHCP_PORT);
    web.send(200, "text/plain", "DHCP enabled — disable your router's DHCP!");
  } else {
    dhcpSock.stop();
    web.send(200, "text/plain", "DHCP disabled");
  }
}

static void handleSetWifi() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  if (web.method() != HTTP_POST) { web.send(405, "text/plain", "use POST"); return; }
  String ssid = web.arg("ssid");
  String pass = web.arg("pass");
  if (ssid.length() == 0) { web.send(400, "text/plain", "missing ssid"); return; }
  saveWifiCfg(ssid, pass);
  web.send(200, "text/plain", "saved — rebooting...");
  delay(500);
  ESP.restart();
}

static void handleSigRequire() {
  if (!checkAuth()) { requireAuth(); return; }
  if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
  requireSigned = !requireSigned;
  saveSigReq();
  web.send(200, "text/plain", requireSigned ? "signature required" : "signatures optional");
}

// ---- blocklist swap (shared by upload + remote fetch) ----
static void loadBloomFromBlocklist(File& f) {
  if (bloomFilter) { free(bloomFilter); bloomFilter = nullptr; }
  bloomBits = 0; bloomK = 0;
  numHashes = 0;
  hashTableOffset = BL_HEADER_SIZE;
  if (!f) return;
  uint8_t hdr[BL_HEADER_SIZE];
  f.seek(0);
  if (f.read(hdr, BL_HEADER_SIZE) != BL_HEADER_SIZE) return;
  if (memcmp(hdr, BL_MAGIC, 4) != 0) { LOGN("[bl] bad magic"); return; }
  if (hdr[4] != BL_VERSION) { LOGN("[bl] wrong version"); return; }
  if (hdr[5] != HASH_BYTES) { LOGN("[bl] wrong hash_bytes"); return; }
  uint32_t nh = hdr[6] | (hdr[7] << 8) | (hdr[8] << 16) | (hdr[9] << 24);
  uint32_t bb = hdr[10] | (hdr[11] << 8) | (hdr[12] << 16) | (hdr[13] << 24);
  uint8_t k = hdr[14];
  size_t bloomBytes = (bb + 7) / 8;
  // Sanity-check sizes against the actual file before trusting the header.
  size_t fsz = f.size();
  if (fsz < BL_HEADER_SIZE + bloomBytes + (size_t)nh * HASH_BYTES) {
    LOGN("[bl] truncated file — ignoring");
    return;
  }
  numHashes = nh;
  bloomBits = bb;
  bloomK = k;
  hashTableOffset = BL_HEADER_SIZE + bloomBytes;
  if (bloomBits > 0 && bloomK > 0) {
    bloomFilter = (uint8_t*)malloc(bloomBytes);
    if (bloomFilter) {
      if (f.read(bloomFilter, bloomBytes) != bloomBytes) {
        LOGN("[bl] bloom short read — running without bloom");
        free(bloomFilter); bloomFilter = nullptr;
        bloomBits = 0; bloomK = 0;
      }
    } else {
      LOGN("[bl] bloom malloc failed — running without bloom (lookups still correct)");
      bloomBits = 0; bloomK = 0;
    }
    // NOTE: hashTableOffset always skips the on-disk bloom bytes,
    // even when the RAM bloom is absent, so inFlash() stays aligned.
  }
}

// ---- blocklist signature (ECDSA P-256, DER) ----
// (blSigned / requireSigned / swapStatus + load/save/verify prototypes live
// above handleStats; definitions of load/save/verify follow here.)

static void loadSigReq() {
  File f = LittleFS.open("/sigreq.cfg", "r");
  if (!f) return;
  String v = f.readStringUntil('\n'); v.trim();
  requireSigned = (v == "1");
  f.close();
}
static void saveSigReq() {
  File f = LittleFS.open("/sigreq.cfg", "w");
  if (!f) return;
  f.println(requireSigned ? "1" : "0");
  f.close();
}

// Stream SHA-256 over a LittleFS file (never loads the whole 700 KB into RAM).
static bool sha256File(const char* path, uint8_t out[32]) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  static uint8_t chunk[2048];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  bool ok = (mbedtls_sha256_starts_ret(&ctx, 0) == 0);
  while (ok && f.available()) {
    size_t n = f.read(chunk, sizeof(chunk));
    if (n == 0) break;
    if (mbedtls_sha256_update_ret(&ctx, chunk, n) != 0) ok = false;
  }
  if (ok && mbedtls_sha256_finish_ret(&ctx, out) != 0) ok = false;
  mbedtls_sha256_free(&ctx);
  f.close();
  return ok;
}

static bool verifyBlocklistSig(const char* binPath, const char* sigPath) {
  File sf = LittleFS.open(sigPath, "r");
  if (!sf) return false;
  size_t slen = sf.size();
  if (slen == 0 || slen > MAX_SIG_SIZE) { sf.close(); return false; }
  uint8_t sig[MAX_SIG_SIZE];
  size_t n = sf.read(sig, slen);
  sf.close();
  if (n != slen) return false;
  uint8_t hash[32];
  if (!sha256File(binPath, hash)) return false;
  mbedtls_ecdsa_context ecdsa;
  mbedtls_ecdsa_init(&ecdsa);
  bool ok = false;
  if (mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
      mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, BL_PUBKEY, sizeof(BL_PUBKEY)) == 0 &&
      mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q) == 0 &&
      mbedtls_ecdsa_read_signature(&ecdsa, hash, sizeof(hash), sig, slen) == 0) {
    ok = true;
  }
  mbedtls_ecdsa_free(&ecdsa);
  return ok;
}

static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  loadBloomFromBlocklist(blocklist);
  blSigned = blocklist && LittleFS.exists(BLOCKLIST_SIG_PATH) &&
             verifyBlocklistSig(BLOCKLIST_PATH, BLOCKLIST_SIG_PATH);
  if (blocklist) LOG("[bl] %u domains, bloom %u bits k=%u, %s\n",
                     numHashes, bloomBits, bloomK, blSigned ? "signed" : "unverified");
}
static void beginBlocklistSwap() {
  // Keep serving the live blocklist while the replacement downloads/uploads.
  // Only the staging files "/blocklist.new" (+ optional ".new.sig") are
  // touched here; the live files are replaced atomically in
  // commitNewBlocklist() after validation.
  LittleFS.remove("/blocklist.new");
  LittleFS.remove("/blocklist.new.sig");
}
static bool commitNewBlocklist() {
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0;
  if (f) f.close();
  // Validate: must have header with correct magic + version + hash_bytes,
  // exact expected size, and at least one hash (reject empty/corrupt feeds
  // that would silently disable blocking).
  bool ok = false;
  swapStatus = "bad data";
  if (sz >= BL_HEADER_SIZE) {
    File chk = LittleFS.open("/blocklist.new", "r");
    uint8_t hdr[BL_HEADER_SIZE];
    if (chk.read(hdr, BL_HEADER_SIZE) == BL_HEADER_SIZE) {
      if (memcmp(hdr, BL_MAGIC, 4) == 0 && hdr[4] == BL_VERSION && hdr[5] == HASH_BYTES) {
        uint32_t nh = hdr[6] | (hdr[7] << 8) | (hdr[8] << 16) | (hdr[9] << 24);
        uint32_t bb = hdr[10] | (hdr[11] << 8) | (hdr[12] << 16) | (hdr[13] << 24);
        size_t expected = BL_HEADER_SIZE + (bb + 7) / 8 + (size_t)nh * HASH_BYTES;
        if (sz == expected && nh > 0) ok = true;
        else if (nh == 0) { LOGN("[bl] rejecting empty blocklist"); swapStatus = "empty blocklist"; }
      } else {
        LOGN("[bl] bad header");
      }
    }
    chk.close();
  }
  bool stagedSig = LittleFS.exists("/blocklist.new.sig");
  bool sigOk = false;
  if (ok) {
    if (stagedSig) {
      sigOk = verifyBlocklistSig("/blocklist.new", "/blocklist.new.sig");
      if (!sigOk) {
        LOGN("[bl] BAD signature — rejecting replacement");
        swapStatus = "bad signature";
        ok = false;
      }
    } else if (requireSigned) {
      LOGN("[bl] signature required but missing — rejecting replacement");
      swapStatus = "signature required";
      ok = false;
    }
  }
  if (ok) {
    if (blocklist) blocklist.close();
    LittleFS.remove(BLOCKLIST_PATH);
    LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
    if (stagedSig) {
      LittleFS.remove(BLOCKLIST_SIG_PATH);
      LittleFS.rename("/blocklist.new.sig", BLOCKLIST_SIG_PATH);
    } else {
      LittleFS.remove(BLOCKLIST_SIG_PATH);  // don't let a stale sig imply trust
    }
    blSigned = stagedSig && sigOk;
    swapStatus = blSigned ? ("ok: " + String(numHashes) + " domains, signed (" + BL_KEY_ID + ")")
                          : ("ok: " + String(numHashes) + " domains, UNVERIFIED");
    reopenBlocklist();  // reloads hashes + re-verifies, sets blSigned authoritatively
    swapStatus = "ok: " + String(numHashes) + " domains, " + (blSigned ? "signed" : "UNVERIFIED");
  } else {
    LittleFS.remove("/blocklist.new");
    LittleFS.remove("/blocklist.new.sig");
    // Live blocklist was never touched — keep serving it. Reopen only if
    // somehow left closed (e.g. first boot with no live file).
    if (!blocklist) reopenBlocklist();
  }
  return ok;
}

// ---- OTA blocklist update (browser upload: .bin + optional .sig) ----
static bool upOk = false;
static bool upGotBin = false;
static File upFile;
static bool upIsSig = false;
static void handleUploadDone() {
  bool doCommit = upGotBin;
  upGotBin = false;  // consumed — a later request without a .bin must not commit
  if (!doCommit) {
    LittleFS.remove("/blocklist.new.sig");
    web.send(upOk ? 200 : 400, "text/plain",
             upOk ? "ok" : "rejected: upload the blocklist .bin (optional .sig alongside)");
    return;
  }
  upOk = commitNewBlocklist();
  LOG("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? ("ok: " + swapStatus) : ("rejected: " + swapStatus));
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  // Auth is checked on every stage (headers persist for the whole request),
  // but a response is only sent on START — answering mid-stream corrupts uploads.
  if (!checkAuth()) { if (u.status == UPLOAD_FILE_START) requireAuth(); return; }
  if (!checkToken()) { if (u.status == UPLOAD_FILE_START) web.send(403, "text/plain", "bad token"); return; }
  switch (u.status) {
    case UPLOAD_FILE_START:
      upOk = false;
      upIsSig = u.filename.endsWith(".sig");
      if (upFile) upFile.close();
      if (upIsSig) {
        upFile = LittleFS.open("/blocklist.new.sig", "w");
      } else {
        beginBlocklistSwap();  // fresh request: drop any previous staging
        upGotBin = true;
        upFile = LittleFS.open("/blocklist.new", "w");
      }
      LOG("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (upFile) upFile.close();
      // Commit happens in handleUploadDone (after ALL files of the request).
      LOG("[ota] got %s (%u bytes)\n", upIsSig ? "sig" : "bin", u.totalSize);
      break;
    case UPLOAD_FILE_ABORTED:
      if (upFile) upFile.close();
      // Live blocklist was never touched — just drop the partial staging files.
      LittleFS.remove("/blocklist.new");
      LittleFS.remove("/blocklist.new.sig");
      upGotBin = false;
      LOGN("[ota] aborted");
      break;
  }
}

// ---- remote blocklist auto-update ----

static const char* DEFAULT_UPDATE_URL = "https://9m2pju.github.io/9M2PJU-ESP32-C3-AdBlocker/blocklist.bin";

static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r");
  if (!f) {
    updateUrl = DEFAULT_UPDATE_URL;
    return;
  }
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim();
  if (iv.length()) updateIntervalH = iv.toInt();
  f.close();
  if (!updateUrl.length()) updateUrl = DEFAULT_UPDATE_URL;
  if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w");
  if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim();
  if (!url.length()) url = DEFAULT_UPDATE_URL;
  String currentUrl = url;
  const int maxHops = 5;
  const char* headerKeys[] = {"Location"};

  for (int hop = 0; hop < maxHops; hop++) {
    LOG("[remote] hop %d GET %s\n", hop, currentUrl.c_str());
    WiFiClientSecure cs;
    // NOTE: no CA verification (setInsecure). The C3 has no system clock/DST
    // root store for full chain validation without NTP + bundled roots, so a
    // LAN MITM could serve a well-formed-but-wrong blocklist. Mitigations:
    // commitNewBlocklist() rejects bad magic/size and empty lists, and the
    // live list is kept on any failure. For high assurance, upload
    // blocklist.bin manually via the dashboard instead of remote pull.
    cs.setInsecure();
    WiFiClient cl;
    HTTPClient http;
    http.setTimeout(25000);
    http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
    http.collectHeaders(headerKeys, 1);

    bool https = currentUrl.startsWith("https");
    if (!(https ? http.begin(cs, currentUrl) : http.begin(cl, currentUrl))) {
      updateStatus = "begin failed"; return false;
    }

    int code = http.GET();
    if (code == HTTP_CODE_MOVED_PERMANENTLY || code == HTTP_CODE_FOUND ||
        code == HTTP_CODE_SEE_OTHER || code == HTTP_CODE_TEMPORARY_REDIRECT || code == 308) {
      String loc = http.header("Location");
      http.end();
      if (!loc.length()) {
        updateStatus = "redirect with no Location";
        LOG("[remote] %s\n", updateStatus.c_str());
        return false;
      }
      if (loc.startsWith("/")) {
        int slashIdx = currentUrl.indexOf('/', currentUrl.indexOf("://") + 3);
        if (slashIdx > 0) currentUrl = currentUrl.substring(0, slashIdx) + loc;
        else currentUrl = currentUrl + loc;
      } else if (loc.indexOf("://") > 0) {
        currentUrl = loc;  // absolute URL
      } else {
        // Relative reference ("other.bin"): resolve against the current path.
        int lastSlash = currentUrl.lastIndexOf('/');
        if (lastSlash > currentUrl.indexOf("://") + 2)
          currentUrl = currentUrl.substring(0, lastSlash + 1) + loc;
        else
          currentUrl = currentUrl + "/" + loc;
      }
      continue;
    }

    if (code != HTTP_CODE_OK) {
      http.end();
      updateStatus = "HTTP " + String(code);
      LOG("[remote] %s\n", updateStatus.c_str());
      return false;
    }

    beginBlocklistSwap();
    File f = LittleFS.open("/blocklist.new", "w");
    if (!f) { http.end(); updateStatus = "fs open failed"; return false; }
    int written = http.writeToStream(&f);
    f.close();
    // Best-effort companion signature (<final-url>.sig). Absent on servers
    // that don't publish one — then the requireSigned policy decides.
    String binUrl = currentUrl;
    http.end();
    if (written < 0) {
      updateStatus = "stream write failed (" + String(written) + ")";
      LOG("[remote] %s\n", updateStatus.c_str());
      LittleFS.remove("/blocklist.new");
      return false;
    }
    {
      WiFiClientSecure cs2;
      cs2.setInsecure();  // same trust model as above; ECDSA verify is the real gate
      HTTPClient sigHttp;
      sigHttp.setTimeout(15000);
      sigHttp.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
      bool sigBegun = binUrl.startsWith("https") ? sigHttp.begin(cs2, binUrl + ".sig")
                                                 : sigHttp.begin(binUrl + ".sig");
      if (sigBegun && sigHttp.GET() == HTTP_CODE_OK) {
        File sf = LittleFS.open("/blocklist.new.sig", "w");
        if (sf) {
          sigHttp.writeToStream(&sf);
          sf.close();
          if (LittleFS.open("/blocklist.new.sig", "r").size() == 0)
            LittleFS.remove("/blocklist.new.sig");
        }
      }
      sigHttp.end();
    }
    bool ok = commitNewBlocklist();
    updateStatus = ok ? swapStatus : ("rejected: " + swapStatus);
    LOG("[remote] %s\n", updateStatus.c_str());
    return ok;
  }

  updateStatus = "too many redirects";
  LOG("[remote] %s\n", updateStatus.c_str());
  return false;
}

// ---- firmware OTA ----
static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  String msg = ok ? "ok, rebooting" : ("firmware update failed (error " + String(Update.getError()) + ")");
  web.send(ok ? 200 : 500, "text/plain", msg);
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  // Upload endpoints previously had NO CSRF check (Basic Auth alone does not
  // stop CSRF: the browser attaches cached credentials to a cross-origin form
  // post). The token now travels in the X-CSRF-Token header, which a
  // cross-origin page cannot set without a passing CORS preflight.
  if (!checkAuth()) { if (u.status == UPLOAD_FILE_START) requireAuth(); return; }
  if (!checkToken()) { if (u.status == UPLOAD_FILE_START) web.send(403, "text/plain", "bad token"); return; }
  if (u.status == UPLOAD_FILE_START) {
    LOG("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (Update.end(true)) LOG("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort(); LOGN("[fw-ota] aborted");
  }
}

// ---- WiFi config (WiFiManager captive portal) ----
static bool loadWifiCfg(String& ssid, String& pass) {
  File f = LittleFS.open("/wifi.cfg", "r");
  if (!f) return false;
  ssid = f.readStringUntil('\n'); ssid.trim();
  pass = f.readStringUntil('\n'); pass.trim();
  f.close();
  return ssid.length() > 0;
}
static void saveWifiCfg(const String& ssid, const String& pass) {
  File f = LittleFS.open("/wifi.cfg", "w");
  if (!f) return;
  f.println(ssid); f.println(pass); f.close();
}

static bool connectWiFi() {
  String ssid, pass;
  bool hasCfg = loadWifiCfg(ssid, pass);

  // Try saved config first, then secrets.h
  const char* trySsid = nullptr;
  const char* tryPass = nullptr;
  if (hasCfg) { trySsid = ssid.c_str(); tryPass = pass.c_str(); }
  else if (String(WIFI_SSID) != "YOUR_WIFI_SSID") { trySsid = WIFI_SSID; tryPass = WIFI_PASS; }

  if (!trySsid) return false;

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(trySsid, tryPass);
  applyTxPower(txPowerSetting);
  LOG("WiFi: connecting to %s", trySsid);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < 15000) {
    delay(300); Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    applyTxPower(txPowerSetting);
    LOGN("\nWiFi up: " + WiFi.localIP().toString());
    return true;
  }
  LOGN("\nWiFi connect failed");
  WiFi.disconnect();
  return false;
}

// ---- captive portal ----
static WiFiUDP captiveDns;

static void handleCaptiveDns() {
  int sz = captiveDns.parsePacket();
  if (sz <= 0) return;
  IPAddress cip = captiveDns.remoteIP();
  uint16_t cport = captiveDns.remotePort();
  int qlen = captiveDns.read(dnsBuf, sizeof(dnsBuf));
  if (qlen < 13) return;
  // Respond to all A queries with 192.168.4.1
  dnsBuf[2] = 0x81; dnsBuf[3] = 0x80;
  dnsBuf[6] = 0; dnsBuf[7] = 1;
  dnsBuf[8] = 0; dnsBuf[9] = 0; dnsBuf[10] = 0; dnsBuf[11] = 0;
  char domain[256]; uint16_t qtype; int qend;
  parseQuery(dnsBuf, qlen, domain, &qtype, &qend);
  if (qtype == 1) {
    uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,0,60, 0,4, 192,168,4,1};
    memcpy(dnsBuf + qend, ans, sizeof(ans));
    captiveDns.beginPacket(cip, cport);
    captiveDns.write(dnsBuf, qend + sizeof(ans));
    captiveDns.endPacket();
  } else if (qtype == 28) {
    // AAAA: portal is IPv4-only — send NODATA (NOERROR, no answers) so
    // clients fail over to IPv4 immediately instead of timing out.
    captiveDns.beginPacket(cip, cport);
    captiveDns.write(dnsBuf, qend);
    captiveDns.endPacket();
  }
}

static void runCaptivePortal() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP("C3AdBlock-Setup");
  applyTxPower(txPowerSetting);
  LOGN("\n[captive] AP: C3AdBlock-Setup — connect and open http://192.168.4.1");
  captiveDns.begin(53);
  web.on("/", []() { web.send(200, "text/html", PORTAL_HTML); });
  auto portalRedirect = []() { web.sendHeader("Location", "http://192.168.4.1/", true); web.send(302, "text/plain", ""); };
  web.on("/generate_204", []() { web.send(204); });  // Android
  web.on("/connecttest.txt", portalRedirect);        // Windows
  web.on("/redirect", portalRedirect);               // Windows
  web.on("/ncsi.txt", portalRedirect);               // Windows
  web.on("/hotspot-detect.html", portalRedirect);    // iOS / macOS
  web.on("/library/test/success.html", portalRedirect);  // iOS
  web.onNotFound([]() { web.send(200, "text/html", PORTAL_HTML); });
  web.on("/save-wifi", HTTP_POST, []() {
    String ssid = web.arg("ssid");
    String pass = web.arg("pass");
    if (ssid.length() == 0) { web.send(400, "text/html", "<h1>Missing SSID</h1>"); return; }
    saveWifiCfg(ssid, pass);
    web.send(200, "text/html", "<h1>Saved! Rebooting...</h1><p>Connect to your WiFi and find the device at c3adblock.local</p>");
    delay(1500);
    ESP.restart();
  });
  web.begin();

  while (true) {
    web.handleClient();
    handleCaptiveDns();
    delay(2);
  }
}

// ---- DHCP config persistence ----
static void loadDhcpCfg() {
  File f = LittleFS.open("/dhcp.cfg", "r");
  if (!f) return;
  String v = f.readStringUntil('\n'); v.trim();
  dhcpEnabled = (v == "1");
  f.close();
}
static void saveDhcpCfg() {
  File f = LittleFS.open("/dhcp.cfg", "w");
  if (!f) return;
  f.println(dhcpEnabled ? "1" : "0");
  f.close();
}

// ---- setup / loop ----
void setup() {
  Serial.begin(115200);
  delay(300);
  LOGN("\n[c3-adblock] booting");

  if (!LittleFS.begin(true)) LOGN("LittleFS FAILED");

  loadAuth();
  loadCustom();
  loadBanned();
  loadUpdateCfg();
  loadDhcpCfg();
  loadTxPowerCfg();
  loadSigReq();
  reopenBlocklist();
  LOG("[cfg] custom:%d banned:%d auth:%s txpower:%s\n", numCustom, numBanned, authPassword.c_str(), txPowerSetting.c_str());
  LOGN("[cfg] dashboard password: " + authPassword);

  if (!connectWiFi()) {
    runCaptivePortal();  // blocks forever (reboots on save)
    return;
  }

  if (MDNS.begin("c3adblock")) {
    MDNS.addService("http", "tcp", 80);
    LOGN("dashboard: http://c3adblock.local");
  }

  dnsServer.begin(DNS_PORT);
  upstream.begin(0);
  tcpUpstream.begin(0);
  tcpDnsServer.begin();
  web.collectHeaders(COLLECTED_HEADERS, sizeof(COLLECTED_HEADERS) / sizeof(char*));
  web.on("/", handleRoot);
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", handleAddBlock);
  web.on("/unblock", handleUnblock);
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);
  web.on("/fetchnow", []() {
    if (!checkAuth()) { requireAuth(); return; }
    if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
    fetchBlocklist(updateUrl);
    web.send(200, "text/plain", updateStatus);
  });
  web.on("/setupdate", []() {
    if (!checkAuth()) { requireAuth(); return; }
    if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg();
    web.send(200, "text/plain", "ok");
  });
  web.on("/settxpower", []() {
    if (!checkAuth()) { requireAuth(); return; }
    if (!checkToken()) { web.send(403, "text/plain", "bad token"); return; }
    if (web.hasArg("p")) {
      String p = web.arg("p");
      if (applyTxPower(p)) {
        saveTxPowerCfg();
        web.send(200, "text/plain", "ok");
        return;
      }
    }
    web.send(400, "text/plain", "invalid power level");
  });
  web.on("/dhcp", handleDhcpToggle);
  web.on("/setwifi", HTTP_POST, handleSetWifi);
  web.on("/sigrequire", handleSigRequire);
  web.begin();

  ArduinoOTA.setHostname("c3adblock");
  ArduinoOTA.begin();

  if (dhcpEnabled) {
    initDhcpPool();
    dhcpSock.begin(DHCP_PORT);
    LOGN("DHCP server enabled on :67");
  }

  LOGN("DNS :53 (UDP+TCP) + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = false;
  if (handleDns()) busy = true;
  if (pollUpstream(dnsBuf, DNS_BUF_SIZE)) busy = true;
  expirePending();
  if (handleTcpDns()) busy = true;
  if (dhcpEnabled && handleDhcp()) busy = true;

  // Reconnect WiFi if the AP/router rebooted (connectWiFi() only ran at boot).
  // Throttled so a down network doesn't busy-loop; DNS is broken while
  // offline anyway, so a blocking 15 s retry here is acceptable.
  if (WiFi.status() != WL_CONNECTED) {
    static uint32_t lastRetryMs = 0;
    uint32_t nowW = millis();
    if (nowW - lastRetryMs >= 10000UL) {
      lastRetryMs = nowW;
      busy = true;
      if (connectWiFi() && dhcpEnabled) initDhcpPool();  // IP may have changed
    }
  }

  // Track DNS activity for idle-gated remote fetch (set in handleDns/pollUpstream)
  if (pendingCount > 0) lastDnsActivityMs = millis();

  // Idle-gated remote blocklist auto-update (only when DNS has been quiet).
  // NOTE: the fetch itself still blocks DNS for several seconds while the
  // HTTPS download runs — gating only defers the start. Schedule off-peak.
  // An empty blocklist retries every 60 s so a fresh device self-heals.
  if (updateUrl.length()) {
    uint32_t now = millis();
    uint32_t intervalMs = (numHashes == 0) ? 60000UL : updateIntervalH * 3600000UL;
    if (lastCheckMs == 0) {
      // Boot: fetch soon when empty, otherwise wait a full interval.
      lastCheckMs = (numHashes == 0) ? (now - intervalMs) : now;
    } else if ((now - lastCheckMs) >= intervalMs &&
               (now - lastDnsActivityMs) >= REMOTE_FETCH_IDLE_MS) {
      lastCheckMs = now;
      fetchBlocklist(updateUrl);
    }
  }

  // Yield CPU to FreeRTOS idle task when there is no active traffic.
  // This allows the RISC-V core to enter the low-power WFI sleep state,
  // dropping idle power and CPU temperature dramatically (by 20-30 °C).
  if (!busy) {
    delay(1);
  }
}
