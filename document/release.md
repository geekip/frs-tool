# Release policy

FRS-TOOL v1 releases are built with Go 1.24.13, `CGO_ENABLED=0`, `-trimpath`, no VCS stamping, and a cleared linker build ID. A release tag must match `vMAJOR.MINOR.PATCH`; the same tag is embedded in `frs version`.

The release workflow builds all eight targets from one locked Ubuntu environment:

| Operating system | Architectures | Archive |
|---|---|---|
| Linux | amd64, arm64 | `.tar.gz` |
| macOS | amd64, arm64 | `.tar.gz` |
| Windows | amd64, arm64 | `.zip` |
| FreeBSD | amd64, arm64 | `.tar.gz` |

Each archive contains the executable, `README.md`, and `config.example.json`. Archive paths, order, modes, owners, timestamps, compression settings, and build flags are fixed. `SHA256SUMS` covers all eight archives. The release job verifies every cross-compiled binary's GOOS, GOARCH, and cgo metadata, checks every archive's structure, and exercises the Linux amd64 archive before publishing.

Native or equivalent execution on all eight targets is maintained separately in `.github/workflows/platform-validation.yml`. That workflow is started manually when platform-specific behavior needs to be revalidated; it does not block routine tag releases.

## Minimum systems

- Linux 5.10 or newer. This is the product support floor even though the locked Go toolchain can run on older kernels.
- macOS 11 Big Sur or newer.
- Windows 10 or Windows Server 2016 or newer.
- FreeBSD 12.0 or newer for amd64 and arm64; the release workflow validates both architectures on FreeBSD 14.3.

The macOS floor follows the [Go 1.24 release notes](https://go.dev/doc/go1.24), while the Windows and FreeBSD floors follow Go's [minimum requirements](https://go.dev/wiki/MinimumRequirements) and [FreeBSD support matrix](https://go.dev/wiki/FreeBSD). These promises cover local filesystems with reliable process locks and same-directory atomic replacement. NFS, SMB, FUSE, and other network or special filesystems are outside the v1 guarantee.

HTTPS downloads use the target system certificate store. Release archives do not bundle CA certificates, DNS configuration, network settings, or rule data.

## Release workflow

Pushing a version tag runs `.github/workflows/release.yml` on one Ubuntu runner. The workflow:

1. validates the tag, exact Go toolchain, tests, vet, and race checks;
2. cross-compiles all eight `CGO_ENABLED=0` binaries and verifies their embedded Go target metadata;
3. creates and structurally validates all eight deterministic archives;
4. runs `version`, a fixed-input build, `verify`, and `inspect` with the native Linux amd64 binary and its unpacked archive;
5. generates and checks `SHA256SUMS`, creates a draft release, and publishes it only after every asset is uploaded.

The manual platform-validation workflow uses native GitHub-hosted Linux, macOS, and Windows runners plus FreeBSD 14.3 virtual machines. Every target runs the full Go suite, builds and exercises its archive, generates the same fixed FRS fixture, and uploads that fixture for an eight-way byte comparison. Cross-compilation in the release workflow does not replace this platform validation; it avoids repeating eight runtime jobs for every patch tag after the platform baseline has already passed.

No package-manager bundle, installer, container image, or automatic updater is part of v1.
