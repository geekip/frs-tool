# FRS-TOOL

FRS-TOOL compiles local and remote text rules into the FRS 1.0 container consumed by FTUN. It is a standalone, standard-library-only Go program and does not add a Go dependency to the FTUN runtime.

The v1 implementation includes strict configuration loading, concurrent acquisition and extraction, deterministic in-memory indexing, a strict writer/verifier, process-level output locking, same-directory atomic publication, inspection commands, and reproducible release packaging. Formal v1 support is granted only by a release whose complete platform workflow has passed.

## Build

Go 1.24.13 is the release toolchain:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off \
  go build -trimpath -buildvcs=false -o frs ./cmd/frs-tool
```

The project has no third-party Go modules. `GOPROXY=off` therefore verifies that ordinary builds and tests do not fetch module dependencies.

## Commands

```text
frs                       Build with config.json beside the resolved executable
frs -c path/config.json   Build with an explicit manifest
frs verify rules.frs      Strictly verify an existing file
frs inspect rules.frs     Verify, then print structural metadata only
frs version               Print tool and FRS format versions
```

Every command accepts `--json`. Controlled JSON results are written as one newline-terminated object to stdout with an empty stderr. In human mode, the final result is written to stdout and warnings or errors are written to stderr.

Exit codes are `0` for success or success with warnings, `1` for a controlled operation failure, `2` for command-line usage errors, and `130` after SIGINT cleanup.

## Configuration

Configuration is strict JSON. Unknown fields, duplicate keys, malformed Unicode, invalid values, and trailing JSON values are rejected before any source is read. There is no top-level version field.

See [config.example.json](config.example.json). The minimal shape is:

```json
{
  "groups": [
    {
      "name": "example",
      "sources": ["rules.txt", "https://example.com/rules.txt"]
    }
  ]
}
```

Relative source and output paths are resolved from the configuration file directory. If `output` is omitted, the result is `<config directory>/rules.frs`.

Supported sources are local paths, local `file` URLs, HTTP, and HTTPS. Remote content must be complete, uncompressed UTF-8 or ASCII text. Source and proxy Basic authentication may be supplied only through URL user information; credentials are removed from diagnostics and never written to FRS output.

The built-in concurrency defaults are 10 global downloads, 3 downloads per host, and 5 file extractors. `max-line-size` defaults to 16 KiB and `max-diagnostics` to 1000. FRS-TOOL does not impose an aggregate input, memory, or output-size budget.

## Publication behavior

FRS-TOOL acquires a non-blocking process lock for the normalized output before source I/O. A concurrent build of the same target fails with `OUTPUT_LOCKED`; different targets can build concurrently.

The complete FRS is written to a private candidate in the output directory, flushed, synchronized, closed, and strictly verified before replacement. Pre-commit failures preserve an existing output. A build producing no usable rules is rejected. Crash leftovers owned by the same target are cleaned after the next successful lock acquisition.

These guarantees apply to supported local filesystems. Network and special filesystems such as NFS, SMB, and FUSE are outside the v1 guarantee.

## Input and format scope

- Mixed files may contain Clash, V2Ray/Geosite text, dnsmasq, SmartDNS domain-set, and plain rules.
- FRS 1.0 supports IPv4 membership and domain exact, suffix, and keyword rules.
- Valid IPv6 rules are counted and filtered in v1.
- Unsupported regular expressions, wildcard forms, and malformed entries are skipped with stable warnings.
- `inspect` exposes format, file, section, and set metadata but never rule payloads or source locations.

The binary layout is documented in [the FRS 1.0 field map](document/frs-1.0-field-map.md).

## Test

```sh
go test ./...
go vet ./...
go test -race ./...
```

The suite covers parsing and configuration boundaries, HTTP behavior, concurrency and backpressure, deterministic indexes, golden FRS bytes, corruption and fuzz cases, output locks, SIGINT cleanup, publication fault injection, CLI streams, and reproducible archives.

The real FTUN C-loader suite is explicit because it requires a local FTUN source tree and C build:

```sh
FTUN_SOURCE_DIR=/path/to/ftun \
FTUN_BUILD_DIR=/path/to/ftun/build/debug \
go test -tags=cinterop ./internal/interop
```

Release targets and system floors are documented in [the release policy](document/release.md).
