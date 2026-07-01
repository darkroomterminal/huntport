# C++ Fast Port Scanner

A high-performance multi-threaded port scanner for Windows written in C++. The project provides fast TCP scanning, service identification, banner grabbing, host discovery, and multiple output formats for network administration, inventory, troubleshooting, and authorized security assessments.

## Features

* Multi-threaded TCP port scanning
* Custom port ranges
* Common-port scanning mode
* Hostname to IP resolution
* Banner grabbing
* Basic service detection
* HTTP title extraction
* CIDR range expansion
* Host discovery (ping-style checks)
* JSON, HTML, and TXT report generation
* Configurable timeout values
* Verbose output mode
* Stealth/randomized scanning options
* Basic OS fingerprinting hints
* CVE reference hints for detected services
* Windows console color support

## Requirements

* Windows 10/11
* Visual Studio (recommended) or MinGW-w64
* Winsock2
* IP Helper API

## Building

### Visual Studio

1. Open the project in Visual Studio.
2. Ensure the following libraries are linked:

   * ws2_32.lib
   * iphlpapi.lib
3. Build the project in Release or Debug mode.

### MinGW

```bash
g++ scanner.cpp -o scanner.exe -lws2_32 -liphlpapi -std=c++17
```

## Usage

Basic scan:

```bash
scanner.exe example.com
```

Scan a port range:

```bash
scanner.exe example.com 1 1000
```

Common ports scan:

```bash
scanner.exe example.com --top-ports
```

Enable verbose output:

```bash
scanner.exe example.com --verbose
```

Save results:

```bash
scanner.exe example.com --json
scanner.exe example.com --html
scanner.exe example.com --txt
```

## Output

The scanner can generate:

* Console output
* JSON reports
* HTML reports
* Text reports

Typical information collected:

* Open ports
* Detected services
* Response times
* Service banners
* HTTP titles
* Additional service metadata

## Security Notice

This software is intended only for:

* Systems you own
* Networks you administer
* Environments where you have explicit authorization

Unauthorized scanning may violate laws, regulations, organizational policies, or service agreements. Users are solely responsible for ensuring compliance with applicable requirements.

## Limitations

* Some detection methods may produce false positives.
* Firewall and IDS/IPS systems can affect results.
* Certain features may require elevated privileges depending on the environment.
* OS fingerprinting is heuristic-based and not guaranteed to be accurate.

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
