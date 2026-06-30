// ============================================================
//  C++ Fast Port Scanner v3.0  — 
//  Features: TCP/UDP scan, banner grab, OS hint, SSL info,
//  HTTP title, version detection, JSON/TXT/HTML output,
//  CIDR range, ping sweep, stealth mode, CVE hints
// ============================================================

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <fstream>
#include <sstream>
#include <set>
#include <map>
#include <random>
#include <iomanip>
#include <regex>
#include <functional>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ── ANSI Colors ───────────────────────────────────────────────────────────────
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define MAGENTA "\033[35m"
#define BLUE    "\033[34m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define RESET   "\033[0m"

void enableColors() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD m = 0;
    GetConsoleMode(h, &m);
    SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

// ── Globals ───────────────────────────────────────────────────────────────────
std::mutex              print_mtx, res_mtx, queue_mtx;
std::condition_variable queue_cv;
std::queue<int>         port_queue;
std::atomic<bool>       done_filling{false};
std::atomic<int>        scanned{0};

// ── Structures ────────────────────────────────────────────────────────────────
struct PortResult {
    int         port     = 0;
    double      ms       = 0.0;
    std::string service;
    std::string banner;
    std::string protocol = "TCP";
    std::string version;
    std::string extra;      // HTTP title, SSL CN, etc.
    std::string state = "open";
    std::string cve_hint;
};

std::vector<PortResult> results;

struct Options {
    std::string           host;
    std::string           ip;
    int                   start_port   = 1;
    int                   end_port     = 1024;
    int                   threads      = 400;
    int                   timeout_ms   = 1200;
    bool                  verbose      = false;
    bool                  save_txt     = false;
    bool                  save_html    = false;
    bool                  save_json    = false;
    bool                  top_ports    = false;
    bool                  ping_first   = false;
    bool                  stealth      = false;   // randomize order + slow
    bool                  udp_scan     = false;
    bool                  os_detect    = false;
    bool                  script_scan  = false;   // HTTP title, SSL, SSH ver
    bool                  show_closed  = false;
    bool                  cidr_mode    = false;
    std::string           output_file  = "scan_result";
    std::vector<int>      custom_ports;
    std::vector<std::string> cidr_hosts;          // expanded from CIDR
};

// ── Top common ports ──────────────────────────────────────────────────────────
static const std::vector<int> TOP_PORTS = {
    21,22,23,25,53,80,88,110,111,119,135,139,143,161,
    389,443,445,465,514,515,587,631,636,873,902,993,
    995,1080,1194,1433,1434,1521,1723,1883,2049,2082,
    2083,2086,2087,2095,2096,3000,3128,3306,3389,3478,
    4443,4444,5000,5060,5432,5601,5900,6379,6443,7001,
    7070,7443,8000,8008,8080,8081,8443,8444,8888,9000,
    9090,9100,9200,9443,10000,11211,27017,27018,49152,
    50000,51820
};

// ── Service name map ──────────────────────────────────────────────────────────
static const std::map<int,std::string> SVC_MAP = {
    {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},
    {53,"DNS"},{80,"HTTP"},{88,"Kerberos"},{110,"POP3"},
    {111,"RPCbind"},{119,"NNTP"},{135,"MS-RPC"},{139,"NetBIOS"},
    {143,"IMAP"},{161,"SNMP"},{389,"LDAP"},{443,"HTTPS"},
    {445,"SMB"},{465,"SMTPS"},{514,"Syslog"},{515,"LPD"},
    {587,"SMTP-Sub"},{631,"IPP"},{636,"LDAPS"},{873,"rsync"},
    {902,"VMware"},{993,"IMAPS"},{995,"POP3S"},{1080,"SOCKS"},
    {1194,"OpenVPN"},{1433,"MSSQL"},{1434,"MSSQL-UDP"},
    {1521,"Oracle"},{1723,"PPTP"},{1883,"MQTT"},
    {2049,"NFS"},{2082,"cPanel"},{2083,"cPanel-SSL"},
    {2086,"WHM"},{2087,"WHM-SSL"},{2095,"cPanel-WM"},
    {2096,"cPanel-WM-SSL"},{3000,"Dev-HTTP"},{3128,"Squid"},
    {3306,"MySQL"},{3389,"RDP"},{3478,"STUN"},
    {4443,"HTTPS-Alt"},{4444,"Metasploit"},{5000,"UPnP"},
    {5060,"SIP"},{5432,"PostgreSQL"},{5601,"Kibana"},
    {5900,"VNC"},{6379,"Redis"},{6443,"K8s-API"},
    {7001,"WebLogic"},{7070,"RealMedia"},{7443,"HTTPS-Alt2"},
    {8000,"HTTP-Dev"},{8008,"HTTP-Alt"},{8080,"HTTP-Alt"},
    {8081,"HTTP-Alt2"},{8443,"HTTPS-Alt"},{8444,"HTTPS-Alt2"},
    {8888,"HTTP-Dev2"},{9000,"PHP-FPM"},{9090,"Prometheus"},
    {9100,"Jetdirect"},{9200,"Elasticsearch"},{9443,"HTTPS-Alt3"},
    {10000,"Webmin"},{11211,"Memcached"},{27017,"MongoDB"},
    {27018,"MongoDB2"},{49152,"Win-RPC"},{50000,"SAP"},
    {51820,"WireGuard"}
};

// ── CVE hint map (service → hint) ────────────────────────────────────────────
static const std::map<std::string,std::string> CVE_HINTS = {
    {"FTP",       "Check: anonymous login, CVE-2011-2523 (vsftpd backdoor)"},
    {"SSH",       "Check: weak creds, CVE-2023-38408 (OpenSSH agent), old versions"},
    {"Telnet",    "CRITICAL: cleartext protocol, disable immediately"},
    {"SMB",       "Check: MS17-010 (EternalBlue), SMBv1 enabled"},
    {"RDP",       "Check: BlueKeep CVE-2019-0708, NLA disabled"},
    {"MySQL",     "Check: anonymous root login, CVE-2012-2122"},
    {"Redis",     "CRITICAL: often no auth, RCE via config write"},
    {"MongoDB",   "Check: no auth by default in older versions"},
    {"Memcached", "Check: UDP amplification DDoS, no auth"},
    {"Elasticsearch","Check: CVE-2015-1427 (Groovy RCE), no auth"},
    {"VNC",       "Check: weak/no password, CVE-2019-15694"},
    {"WebLogic",  "Check: CVE-2020-14882 RCE, T3 deserialization"},
    {"Webmin",    "Check: CVE-2019-15107 RCE (unauthenticated)"},
    {"MQTT",      "Check: no auth broker, subscribe to all topics"},
    {"Metasploit","WARNING: Metasploit listener port detected"},
    {"SNMP",      "Check: community string 'public', CVE-2017-6736"},
};

// ── Helper: get service name ──────────────────────────────────────────────────
std::string svcName(int port) {
    auto it = SVC_MAP.find(port);
    return (it != SVC_MAP.end()) ? it->second : "unknown";
}

// ── Helper: get CVE hint ──────────────────────────────────────────────────────
std::string getCveHint(const std::string& svc) {
    auto it = CVE_HINTS.find(svc);
    return (it != CVE_HINTS.end()) ? it->second : "";
}

// ── Resolve hostname → IP ─────────────────────────────────────────────────────
std::string resolve(const std::string& host) {
    addrinfo hints{}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return "";
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr, ip, sizeof(ip));
    freeaddrinfo(res);
    return ip;
}

// ── Expand CIDR (e.g. 192.168.1.0/24) → list of IPs ─────────────────────────
std::vector<std::string> expandCIDR(const std::string& cidr) {
    std::vector<std::string> ips;
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) { ips.push_back(cidr); return ips; }

    std::string base = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 32) return ips;

    in_addr addr{};
    if (inet_pton(AF_INET, base.c_str(), &addr) != 1) return ips;

    uint32_t ip_int   = ntohl(addr.s_addr);
    uint32_t mask     = (prefix == 0) ? 0 : (~0u << (32 - prefix));
    uint32_t net_addr = ip_int & mask;
    uint32_t bc_addr  = net_addr | (~mask);

    // Safety cap: max /16 = 65536 hosts
    if ((bc_addr - net_addr + 1) > 65536) {
        std::cout << RED << "[-] CIDR too large (max /16)" << RESET << "\n";
        return ips;
    }
    for (uint32_t h = net_addr + 1; h < bc_addr; h++) {
        uint32_t n = htonl(h);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &n, buf, sizeof(buf));
        ips.push_back(buf);
    }
    return ips;
}

// ── ICMP ping (Windows: uses TTL trick via TCP connect to port 80/443) ────────
bool pingHost(const std::string& ip, int timeout_ms = 1500) {
    // Windows raw ICMP needs admin; use fast TCP connect as proxy
    for (int p : {80, 443, 22, 21, 3389}) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(p);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        connect(s, (sockaddr*)&addr, sizeof(addr));
        fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        bool up = false;
        if (select(0, nullptr, &wfds, nullptr, &tv) > 0) {
            int err = 0, len = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
            if (err == 0) up = true;
        }
        u_long bl = 0; ioctlsocket(s, FIONBIO, &bl);
        closesocket(s);
        if (up) return true;
    }
    return false;
}

// ── Get TTL to guess OS ───────────────────────────────────────────────────────
std::string guessTTL(const std::string& ip) {
    // Use IP_TTL socket option after connect to measure approximate hop distance
    // Simplified: send a TCP connect and read TTL from SO_TTL (not directly available)
    // We approximate using a known heuristic ping
    // Real implementation would use raw sockets (needs admin) - we use banner clues instead
    return "";
}

// ── Script: grab HTTP title ───────────────────────────────────────────────────
std::string httpTitle(const std::string& ip, int port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";
    DWORD to = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s); return ""; }

    std::string req = "GET / HTTP/1.0\r\nHost: " + ip + "\r\nUser-Agent: Scanner/3.0\r\n\r\n";
    send(s, req.c_str(), (int)req.size(), 0);

    char buf[4096] = {};
    std::string resp;
    int n;
    while ((n = recv(s, buf, sizeof(buf)-1, 0)) > 0) {
        resp += std::string(buf, n);
        if (resp.size() > 8192) break;
    }
    closesocket(s);

    // Extract <title>
    std::string lower = resp;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    size_t ts = lower.find("<title>");
    size_t te = lower.find("</title>", ts);
    if (ts != std::string::npos && te != std::string::npos) {
        std::string title = resp.substr(ts + 7, te - ts - 7);
        // trim
        title.erase(0, title.find_first_not_of(" \t\r\n"));
        title.erase(title.find_last_not_of(" \t\r\n") + 1);
        if (title.size() > 60) title = title.substr(0, 60) + "...";
        return "title=" + title;
    }

    // If no title, check Server header
    size_t sh = lower.find("server:");
    if (sh != std::string::npos) {
        size_t el = resp.find('\n', sh);
        std::string srv = resp.substr(sh + 7, el - sh - 7);
        srv.erase(std::remove(srv.begin(), srv.end(), '\r'), srv.end());
        srv.erase(0, srv.find_first_not_of(' '));
        if (srv.size() > 50) srv = srv.substr(0, 50);
        return "server=" + srv;
    }
    return "";
}

// ── Script: detect version from banner ───────────────────────────────────────
std::string detectVersion(int port, const std::string& banner) {
    if (banner.empty()) return "";

    // SSH version
    if (port == 22 && banner.substr(0, 4) == "SSH-")
        return banner.substr(0, std::min((int)banner.size(), 40));

    // FTP
    if (port == 21) {
        size_t sp = banner.find(' ');
        if (sp != std::string::npos)
            return banner.substr(sp+1, std::min((size_t)40, banner.size()-sp-1));
    }

    // SMTP
    if (port == 25 || port == 587 || port == 465) {
        if (banner.size() > 4)
            return banner.substr(4, std::min((size_t)45, banner.size()-4));
    }

    // HTTP Server header (already in banner)
    if ((port == 80 || port == 8080 || port == 8888 || port == 8000) &&
        banner.find("HTTP/") == 0) {
        size_t nl = banner.find('\n');
        return banner.substr(0, std::min((size_t)40, nl));
    }

    return banner.substr(0, std::min((size_t)40, banner.size()));
}

// ── Banner grabber ────────────────────────────────────────────────────────────
std::string grabBanner(const std::string& ip, int port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";
    DWORD to = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s); return ""; }

    // Port-specific probes
    if (port == 80 || port == 8080 || port == 8888 || port == 8000 || port == 8008) {
        std::string req = "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\nUser-Agent: Scanner/3.0\r\n\r\n";
        send(s, req.c_str(), (int)req.size(), 0);
    } else if (port == 21 || port == 22 || port == 25 || port == 110 ||
               port == 143 || port == 587 || port == 993 || port == 995) {
        // Wait for server banner (these protocols send first)
    } else if (port == 3306) {
        // MySQL sends greeting, just wait
    } else {
        std::string probe = "\r\n";
        send(s, probe.c_str(), (int)probe.size(), 0);
    }

    char buf[1024] = {};
    int n = recv(s, buf, sizeof(buf)-1, 0);
    closesocket(s);
    if (n <= 0) return "";

    std::string banner(buf, n);
    // Keep only first line
    size_t nl = banner.find('\n');
    if (nl != std::string::npos) banner = banner.substr(0, nl);
    banner.erase(std::remove(banner.begin(), banner.end(), '\r'), banner.end());
    // Remove non-printable
    banner.erase(std::remove_if(banner.begin(), banner.end(),
        [](char c){ return (unsigned char)c < 32 && c != '\t'; }), banner.end());
    if (banner.size() > 80) banner = banner.substr(0, 80) + "...";
    return banner;
}

// ── UDP port scan (basic) ────────────────────────────────────────────────────
bool scanUDP(const std::string& ip, int port, int timeout_ms, PortResult& out) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;
    DWORD to = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Port-specific UDP probes
    std::string probe = "\x00";
    if (port == 53)   probe = "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"; // DNS version
    if (port == 161)  probe = "\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x01\x02\x03\x04\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"; // SNMP
    if (port == 1194) probe = std::string(10, '\x38'); // OpenVPN
    if (port == 51820) probe = std::string(32, '\x00'); // WireGuard handshake init

    auto t0 = std::chrono::high_resolution_clock::now();
    sendto(s, probe.c_str(), (int)probe.size(), 0, (sockaddr*)&addr, sizeof(addr));

    char buf[512] = {};
    sockaddr_in from{};
    int fromlen = sizeof(from);
    int n = recvfrom(s, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fromlen);
    closesocket(s);

    if (n > 0) {
        auto t1 = std::chrono::high_resolution_clock::now();
        out.port     = port;
        out.ms       = std::chrono::duration<double, std::milli>(t1 - t0).count();
        out.service  = svcName(port);
        out.protocol = "UDP";
        out.banner   = (n > 0) ? "[UDP response received]" : "";
        out.cve_hint = getCveHint(out.service);
        return true;
    }
    return false;
}

// ── TCP port scan ─────────────────────────────────────────────────────────────
bool scanPort(const std::string& ip, int port, int timeout_ms, PortResult& out,
              bool script_scan) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    auto t0 = std::chrono::high_resolution_clock::now();
    connect(s, (sockaddr*)&addr, sizeof(addr));

    fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    bool open = false;

    if (select(0, nullptr, &wfds, nullptr, &tv) > 0) {
        int err = 0, len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        if (err == 0) {
            auto t1 = std::chrono::high_resolution_clock::now();
            out.port     = port;
            out.ms       = std::chrono::duration<double, std::milli>(t1 - t0).count();
            out.service  = svcName(port);
            out.protocol = "TCP";
            open = true;
        }
    }

    u_long bl = 0; ioctlsocket(s, FIONBIO, &bl);
    closesocket(s);

    if (open) {
        out.banner   = grabBanner(ip, port, timeout_ms);
        out.version  = detectVersion(port, out.banner);
        out.cve_hint = getCveHint(out.service);

        // Script scan extras
        if (script_scan) {
            if (port == 80 || port == 8080 || port == 8000 ||
                port == 8008 || port == 8888 || port == 8081) {
                out.extra = httpTitle(ip, port, timeout_ms);
            }
        }
    }
    return open;
}

// ── Worker thread ─────────────────────────────────────────────────────────────
void worker(const std::string& ip, int total, int timeout_ms,
            bool verbose, bool script_scan, bool udp_scan) {
    while (true) {
        int port = -1;
        {
            std::unique_lock<std::mutex> lk(queue_mtx);
            queue_cv.wait(lk, []{ return !port_queue.empty() || done_filling; });
            if (port_queue.empty()) break;
            port = port_queue.front();
            port_queue.pop();
        }

        PortResult r{};
        bool open = false;

        if (udp_scan)
            open = scanUDP(ip, port, timeout_ms, r);
        else
            open = scanPort(ip, port, timeout_ms, r, script_scan);

        if (open) {
            {
                std::lock_guard<std::mutex> lk(res_mtx);
                results.push_back(r);
            }
            std::lock_guard<std::mutex> lk(print_mtx);
            std::cout << GREEN << "[OPEN] " << RESET
                      << BOLD << std::setw(6) << r.port << RESET
                      << "  " << CYAN << std::left << std::setw(15) << r.service << RESET
                      << "  " << DIM  << r.protocol << RESET
                      << "  " << std::fixed << std::setprecision(1) << r.ms << "ms";
            if (!r.version.empty())
                std::cout << "  " << MAGENTA << r.version << RESET;
            if (!r.extra.empty())
                std::cout << "  " << YELLOW << r.extra << RESET;
            if (!r.cve_hint.empty())
                std::cout << "\n        " << RED << "[!] " << r.cve_hint << RESET;
            std::cout << "\n";
        } else if (verbose) {
            std::lock_guard<std::mutex> lk(print_mtx);
            std::cout << RED << "[----] " << RESET
                      << std::setw(6) << port << "  "
                      << DIM << svcName(port) << "  closed" << RESET << "\n";
        }

        int done = ++scanned;
        if (done % 500 == 0 && !verbose) {
            std::lock_guard<std::mutex> lk(print_mtx);
            int pct = (int)(100.0 * done / total);
            std::cout << "\r" << CYAN << " [" << std::setw(3) << pct << "%] "
                      << done << "/" << total << " ports scanned" << RESET
                      << "        " << std::flush;
        }
    }
}

// ── Ping sweep ────────────────────────────────────────────────────────────────
std::vector<std::string> pingSweep(const std::vector<std::string>& hosts, int timeout_ms) {
    std::vector<std::string> alive;
    std::mutex alive_mtx;
    std::vector<std::thread> threads;

    for (const auto& h : hosts) {
        threads.emplace_back([&, h]() {
            if (pingHost(h, timeout_ms)) {
                std::lock_guard<std::mutex> lk(alive_mtx);
                alive.push_back(h);
                std::lock_guard<std::mutex> lk2(print_mtx);
                std::cout << GREEN << "[UP]  " << RESET << h << "\n";
            }
        });
        if (threads.size() % 100 == 0) {
            for (auto& t : threads) if (t.joinable()) t.join();
            threads.clear();
        }
    }
    for (auto& t : threads) if (t.joinable()) t.join();
    return alive;
}

// ── Save TXT ──────────────────────────────────────────────────────────────────
void saveTXT(const Options& opt, double elapsed) {
    std::string fname = opt.output_file + ".txt";
    std::ofstream f(fname);
    f << "==============================================\n";
    f << "  C++ Port Scanner v3.0 Report\n";
    f << "==============================================\n";
    f << "Target   : " << opt.host << " (" << opt.ip << ")\n";
    f << "Ports    : " << opt.start_port << "-" << opt.end_port << "\n";
    f << "Protocol : " << (opt.udp_scan ? "UDP" : "TCP") << "\n";
    f << "Time     : " << std::fixed << std::setprecision(2) << elapsed << "s\n";
    f << "Open     : " << results.size() << "\n\n";
    f << std::left
      << std::setw(7)  << "PORT"
      << std::setw(6)  << "PROTO"
      << std::setw(16) << "SERVICE"
      << std::setw(10) << "TIME"
      << "BANNER / VERSION\n";
    f << std::string(80, '-') << "\n";
    for (auto& r : results) {
        f << std::setw(7)  << r.port
          << std::setw(6)  << r.protocol
          << std::setw(16) << r.service
          << std::setw(10) << (std::to_string((int)r.ms) + "ms");
        if (!r.version.empty()) f << r.version;
        else if (!r.banner.empty()) f << r.banner;
        f << "\n";
        if (!r.extra.empty())    f << "         [script] " << r.extra << "\n";
        if (!r.cve_hint.empty()) f << "         [!] CVE: " << r.cve_hint << "\n";
    }
    f << "\n==============================================\n";
    std::cout << GREEN << "[+] Saved: " << fname << RESET << "\n";
}

// ── Save HTML ─────────────────────────────────────────────────────────────────
void saveHTML(const Options& opt, double elapsed) {
    std::string fname = opt.output_file + ".html";
    std::ofstream f(fname);
    f << R"(<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Scanner Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:24px}
h1{color:#58a6ff;font-size:22px;margin-bottom:4px}
.meta{color:#8b949e;font-size:13px;margin-bottom:20px;line-height:1.8}
table{border-collapse:collapse;width:100%;margin-top:12px}
th{background:#161b22;color:#58a6ff;padding:10px 14px;text-align:left;font-size:13px;
   border-bottom:2px solid #30363d}
td{padding:9px 14px;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top}
tr:hover td{background:#161b22}
.port{color:#3fb950;font-weight:bold;font-size:14px}
.svc{color:#79c0ff}
.banner{color:#e3b341;font-size:12px}
.extra{color:#a5d6ff;font-size:12px}
.cve{color:#ff7b72;font-size:12px;font-weight:bold}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;
       font-size:11px;font-weight:bold}
.tcp{background:#0d419d;color:#79c0ff}
.udp{background:#3d2b00;color:#e3b341}
.summary{background:#161b22;border:1px solid #30363d;border-radius:8px;
         padding:16px;margin-bottom:20px;display:flex;gap:40px}
.stat{text-align:center}
.stat-num{font-size:28px;font-weight:bold;color:#58a6ff}
.stat-lbl{font-size:12px;color:#8b949e;margin-top:4px}
</style></head><body>
<h1>&#128269; Port Scanner Report v3.0</h1>
)";
    f << "<div class='meta'>"
      << "Target: <b>" << opt.host << "</b> (" << opt.ip << ")<br>"
      << "Protocol: " << (opt.udp_scan ? "UDP" : "TCP") << " &nbsp;|&nbsp; "
      << "Ports: " << opt.start_port << " – " << opt.end_port << "<br>"
      << "Scan time: " << std::fixed << std::setprecision(2) << elapsed << "s"
      << "</div>\n";

    f << "<div class='summary'>"
      << "<div class='stat'><div class='stat-num'>" << results.size() << "</div>"
      << "<div class='stat-lbl'>OPEN PORTS</div></div>"
      << "<div class='stat'><div class='stat-num'>"
      << (int)(results.size() > 0 ? (opt.end_port - opt.start_port + 1) : 0)
      << "</div><div class='stat-lbl'>TOTAL SCANNED</div></div>"
      << "<div class='stat'><div class='stat-num'>"
      << (int)((opt.end_port - opt.start_port + 1) / (elapsed > 0 ? elapsed : 1))
      << "</div><div class='stat-lbl'>PORTS/SEC</div></div>"
      << "</div>\n";

    f << "<table><tr><th>Port</th><th>Proto</th><th>Service</th>"
      << "<th>Latency</th><th>Version / Banner</th><th>Script / CVE</th></tr>\n";

    for (auto& r : results) {
        f << "<tr>"
          << "<td class='port'>" << r.port << "</td>"
          << "<td><span class='badge " << (r.protocol == "UDP" ? "udp" : "tcp") << "'>"
          << r.protocol << "</span></td>"
          << "<td class='svc'>" << r.service << "</td>"
          << "<td>" << std::fixed << std::setprecision(1) << r.ms << "ms</td>"
          << "<td class='banner'>";
        if (!r.version.empty()) f << r.version;
        else if (!r.banner.empty()) f << r.banner;
        f << "</td><td>";
        if (!r.extra.empty())
            f << "<span class='extra'>&#128202; " << r.extra << "</span><br>";
        if (!r.cve_hint.empty())
            f << "<span class='cve'>&#9888; " << r.cve_hint << "</span>";
        f << "</td></tr>\n";
    }
    f << "</table></body></html>";
    std::cout << GREEN << "[+] Saved: " << fname << RESET << "\n";
}

// ── Save JSON ─────────────────────────────────────────────────────────────────
void saveJSON(const Options& opt, double elapsed) {
    std::string fname = opt.output_file + ".json";
    std::ofstream f(fname);
    f << "{\n";
    f << "  \"target\": \"" << opt.host << "\",\n";
    f << "  \"ip\": \"" << opt.ip << "\",\n";
    f << "  \"scan_time\": " << std::fixed << std::setprecision(3) << elapsed << ",\n";
    f << "  \"open_ports\": " << results.size() << ",\n";
    f << "  \"ports\": [\n";
    for (size_t i = 0; i < results.size(); i++) {
        const auto& r = results[i];
        auto esc = [](const std::string& s) {
            std::string out;
            for (char c : s) {
                if (c == '"') out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else out += c;
            }
            return out;
        };
        f << "    {";
        f << "\"port\":" << r.port << ",";
        f << "\"protocol\":\"" << r.protocol << "\",";
        f << "\"service\":\"" << r.service << "\",";
        f << "\"state\":\"open\",";
        f << "\"latency_ms\":" << std::fixed << std::setprecision(2) << r.ms << ",";
        f << "\"version\":\"" << esc(r.version) << "\",";
        f << "\"banner\":\"" << esc(r.banner) << "\",";
        f << "\"extra\":\"" << esc(r.extra) << "\",";
        f << "\"cve_hint\":\"" << esc(r.cve_hint) << "\"";
        f << "}" << (i + 1 < results.size() ? "," : "") << "\n";
    }
    f << "  ]\n}\n";
    std::cout << GREEN << "[+] Saved: " << fname << RESET << "\n";
}

// ── Print help ────────────────────────────────────────────────────────────────
void printHelp(const char* prog) {
    std::cout << BOLD
<< "\n  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗  ██╗\n"
<< "  ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║\n"
<< "  ██████╔╝██████╔╝██████╔╝███████╗██║     ███████║██╔██╗██║\n"
<< "  ██╔═══╝ ██╔═══╝ ██╔═══╝ ╚════██║██║     ██╔══██║██║╚████║\n"
<< "  ██║     ██║     ██║     ███████║╚██████╗██║  ██║██║ ╚███║\n"
<< "  ╚═╝     ╚═╝     ╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝\n"
<< RESET
<< CYAN << "  C++ Fast Port Scanner v3.0  —  nmap-inspired\n\n" << RESET
<< BOLD << "USAGE:\n" << RESET
<< "  " << prog << " <target> [options]\n\n"
<< BOLD << "TARGET:\n" << RESET
<< "  hostname, IP, or CIDR   e.g. scanme.nmap.org  192.168.1.0/24\n\n"
<< BOLD << "PORT SELECTION:\n" << RESET
<< "  -p <start>-<end>     Range          e.g. -p 1-65535\n"
<< "  -p <p1,p2,...>       Specific       e.g. -p 22,80,443\n"
<< "  -p-                  All ports (1-65535)\n"
<< "  --top                Top " << TOP_PORTS.size() << " common ports (default)\n\n"
<< BOLD << "SCAN TYPE:\n" << RESET
<< "  (default)            TCP connect scan\n"
<< "  -sU                  UDP scan (top UDP ports)\n"
<< "  --ping               Ping sweep only (CIDR)\n\n"
<< BOLD << "SPEED:\n" << RESET
<< "  -T <1-5>             1=slow/stealth  3=normal  5=insane\n"
<< "                       T1=50  T2=100  T3=200  T4=400  T5=800 threads\n"
<< "  --timeout <ms>       Per-port timeout (default: 1200ms)\n"
<< "  --stealth            Randomize port order + slower pace\n\n"
<< BOLD << "OUTPUT:\n" << RESET
<< "  -v                   Verbose (show closed ports)\n"
<< "  -o <file>            Save TXT report\n"
<< "  --html <file>        Save HTML report (open in browser)\n"
<< "  --json <file>        Save JSON report\n\n"
<< BOLD << "SCRIPTS (--script):\n" << RESET
<< "  --script             Enable script scan:\n"
<< "                         http-title   : Grab HTML page title\n"
<< "                         banner       : Grab service banners\n"
<< "                         version      : Detect service version\n"
<< "                         cve-hint     : Show known CVE warnings\n\n"
<< BOLD << "EXAMPLES:\n" << RESET
<< "  " << prog << " scanme.nmap.org\n"
<< "  " << prog << " scanme.nmap.org -p- -T5 --script\n"
<< "  " << prog << " scanme.nmap.org --top --script --html report\n"
<< "  " << prog << " 192.168.1.1 -p 1-1024 -T4 -o myscan\n"
<< "  " << prog << " 192.168.1.0/24 --ping            (ping sweep)\n"
<< "  " << prog << " 192.168.1.1 -sU                  (UDP scan)\n"
<< "  " << prog << " 192.168.1.1 -p 22,80,443 --script --json out\n\n";
}

// ── Parse -p argument ─────────────────────────────────────────────────────────
void parsePortArg(const std::string& arg, Options& opt) {
    if (arg == "-") { opt.start_port = 1; opt.end_port = 65535; return; }
    if (arg.find(',') != std::string::npos) {
        std::stringstream ss(arg);
        std::string tok;
        while (std::getline(ss, tok, ','))
            if (!tok.empty()) opt.custom_ports.push_back(std::stoi(tok));
        return;
    }
    size_t dash = arg.find('-');
    if (dash != std::string::npos) {
        opt.start_port = std::stoi(arg.substr(0, dash));
        opt.end_port   = std::stoi(arg.substr(dash + 1));
    } else {
        opt.start_port = opt.end_port = std::stoi(arg);
    }
}

// ── Scan one host ─────────────────────────────────────────────────────────────
void scanHost(Options opt) {
    results.clear();
    while (!port_queue.empty()) port_queue.pop();
    done_filling = false;
    scanned = 0;

    // Resolve
    std::cout << CYAN << "[*] Resolving " << opt.host << "..." << RESET << "\n";
    opt.ip = resolve(opt.host);
    if (opt.ip.empty()) {
        // Try as raw IP
        in_addr test{};
        if (inet_pton(AF_INET, opt.host.c_str(), &test) == 1)
            opt.ip = opt.host;
        else {
            std::cout << RED << "[-] Could not resolve: " << opt.host << RESET << "\n";
            return;
        }
    }

    // Build port list
    std::vector<int> ports;
    if (!opt.custom_ports.empty())    ports = opt.custom_ports;
    else if (opt.top_ports)           ports = std::vector<int>(TOP_PORTS.begin(), TOP_PORTS.end());
    else {
        for (int p = opt.start_port; p <= opt.end_port; p++) ports.push_back(p);
    }

    // Stealth: randomize order
    if (opt.stealth) {
        std::mt19937 rng(std::random_device{}());
        std::shuffle(ports.begin(), ports.end(), rng);
        if (opt.threads > 50) opt.threads = 50;
        if (opt.timeout_ms < 2000) opt.timeout_ms = 2000;
        std::cout << YELLOW << "[stealth] Port order randomized, throttled to 50 threads\n" << RESET;
    }

    int total = (int)ports.size();

    // Print header
    std::cout << BOLD
              << "\n+--------------------------------------------------+\n"
              << "|       C++ Fast Port Scanner v3.0                |\n"
              << "|       Use --help for full manual                 |\n"
              << "+--------------------------------------------------+\n" << RESET
              << CYAN  << " Target  : " << RESET << opt.host << " (" << opt.ip << ")\n"
              << CYAN  << " Ports   : " << RESET;
    if (!opt.custom_ports.empty())      std::cout << "Custom (" << total << " ports)\n";
    else if (opt.top_ports)             std::cout << "Top " << total << " common ports\n";
    else                                std::cout << opt.start_port << " – " << opt.end_port << "\n";
    std::cout << CYAN  << " Protocol: " << RESET << (opt.udp_scan ? "UDP" : "TCP") << "\n"
              << CYAN  << " Threads : " << RESET << opt.threads << "\n"
              << CYAN  << " Timeout : " << RESET << opt.timeout_ms << "ms\n"
              << CYAN  << " Scripts : " << RESET << (opt.script_scan ? "ON" : "OFF") << "\n"
              << CYAN  << " Stealth : " << RESET << (opt.stealth ? "ON" : "OFF") << "\n"
              << CYAN  << " Total   : " << RESET << total << " ports\n\n"
              << BOLD
              << " PORT    SERVICE          PROTO  LATENCY  VERSION / BANNER\n"
              << " " << std::string(72, '-') << "\n" << RESET;

    // Fill queue
    for (int p : ports) {
        std::lock_guard<std::mutex> lk(queue_mtx);
        port_queue.push(p);
    }
    done_filling = true;
    queue_cv.notify_all();

    // Run threads
    auto t0 = std::chrono::high_resolution_clock::now();
    std::vector<std::thread> threads;
    for (int i = 0; i < std::min(opt.threads, total); i++)
        threads.emplace_back(worker, std::ref(opt.ip), total,
                             opt.timeout_ms, opt.verbose,
                             opt.script_scan, opt.udp_scan);
    queue_cv.notify_all();
    for (auto& t : threads) t.join();
    auto t1 = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    // Sort by port
    std::sort(results.begin(), results.end(),
        [](const PortResult& a, const PortResult& b){ return a.port < b.port; });

    // Summary
    std::cout << "\n\n" << BOLD
              << " ================ SUMMARY ================\n" << RESET
              << GREEN  << " Open ports  : " << RESET << results.size() << "\n"
              << CYAN   << " Scanned     : " << RESET << total << " ports\n"
              << YELLOW << " Time taken  : " << RESET
                        << std::fixed << std::setprecision(2) << elapsed << "s\n"
              << YELLOW << " Speed       : " << RESET
                        << (int)(total / (elapsed > 0 ? elapsed : 1)) << " ports/sec\n";

    if (!results.empty()) {
        std::cout << "\n" << BOLD << " Open Port Summary:\n" << RESET;
        for (auto& r : results) {
            std::cout << "  " << GREEN << r.port << RESET
                      << "/" << DIM << r.protocol << RESET
                      << "  " << CYAN << r.service << RESET;
            if (!r.version.empty()) std::cout << "  " << MAGENTA << r.version << RESET;
            std::cout << "\n";
        }
    }

    std::cout << "\n";
    if (opt.save_txt)  saveTXT(opt, elapsed);
    if (opt.save_html) saveHTML(opt, elapsed);
    if (opt.save_json) saveJSON(opt, elapsed);
}

// ── Main ──────────────────────────────────────────────────────────────────────
int runHuntPortCommand(const std::vector<std::string>& args);

int main(int argc, char* argv[]) {
    enableColors();
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (argc < 2) {
    std::cout << "HuntPort v3.0\n\n";
    std::cout << "Usage:\n";
    std::cout << "  huntport <target> [options]\n\n";
    std::cout << "Examples:\n";
    std::cout << "  huntport 192.168.1.1\n";
    std::cout << "  huntport scanme.nmap.org -p 1-1000\n";
    return 0;
}

    std::string target = argv[1];
    if (target == "-h" || target == "--help") {
        printHelp(argv[0]); WSACleanup(); return 0;
    }

    Options opt;
    opt.host      = target;
    opt.top_ports = true; // default: top ports

    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if      (a == "-p"  && i+1 < argc) { opt.top_ports = false; parsePortArg(argv[++i], opt); }
        else if (a == "-p-")               { opt.top_ports = false; opt.start_port = 1; opt.end_port = 65535; }
        else if (a == "--top")             { opt.top_ports = true; }
        else if (a == "-sU")               { opt.udp_scan = true; }
        else if (a == "--script")          { opt.script_scan = true; }
        else if (a == "--stealth")         { opt.stealth = true; }
        else if (a == "--ping")            { opt.ping_first = true; }
        else if (a == "-v")                { opt.verbose = true; }
        else if (a == "-T" && i+1 < argc) {
            int t = std::stoi(argv[++i]);
            int tmap[] = {0, 50, 100, 200, 400, 800};
            opt.threads = (t >= 1 && t <= 5) ? tmap[t] : 400;
        }
        else if (a == "--timeout" && i+1 < argc) opt.timeout_ms = std::stoi(argv[++i]);
        else if (a == "-o"     && i+1 < argc) { opt.save_txt  = true; opt.output_file = argv[++i]; }
        else if (a == "--html" && i+1 < argc) { opt.save_html = true; opt.output_file = argv[++i]; }
        else if (a == "--json" && i+1 < argc) { opt.save_json = true; opt.output_file = argv[++i]; }
        else if (a == "-h" || a == "--help")  { printHelp(argv[0]); WSACleanup(); return 0; }
    }

    // CIDR detection
    bool is_cidr = opt.host.find('/') != std::string::npos;

    if (is_cidr || opt.ping_first) {
        std::vector<std::string> hosts;
        if (is_cidr) {
            hosts = expandCIDR(opt.host);
            std::cout << CYAN << "[*] CIDR expanded to " << hosts.size()
                      << " hosts\n" << RESET;
        } else {
            hosts.push_back(opt.host);
        }

        if (opt.ping_first || is_cidr) {
            std::cout << CYAN << "[*] Ping sweep...\n" << RESET;
            hosts = pingSweep(hosts, opt.timeout_ms);
            std::cout << GREEN << "[*] " << hosts.size() << " host(s) alive\n\n" << RESET;
        }

        for (const auto& h : hosts) {
            opt.host = h;
            opt.ip   = "";
            scanHost(opt);
        }
    } else {
        scanHost(opt);
    }

    WSACleanup();
    return 0;
}

// ── Integration: call from another module ────────────────────────────────────
int runHuntPortCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << "Usage: huntport <target> [options]\n"; return 1; }
    // Rebuild argc/argv style
    std::vector<const char*> argv_v;
    for (auto& s : args) argv_v.push_back(s.c_str());
    return main((int)argv_v.size(), const_cast<char**>(argv_v.data()));
}
