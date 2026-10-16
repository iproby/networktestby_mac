# Native releases

`python scripts/build_native.py` bundles Python, Textual, psutil and DNS dependencies into one console executable. Build on each target OS; cross-compilation is unsupported. The CI matrix builds Linux x86_64 (glibc 2.35+), macOS ARM64/Intel and Windows x64, runs tests and uploads binaries and SHA-256 files. Linux ARM64 needs an ARM64 runner, using the same script. Native iOS/Android apps are outside this terminal app's supported platforms.

Tag `v4.x.y` creates a **draft**, never an automatically published release. The source launch command remains available independently of releases.

Before publishing a signed release:

1. In a macOS keychain import your Apple Developer ID Application certificate using secure CI secret storage. Build with `python scripts/build_native.py --identity 'Developer ID Application: ...'`. Verify `codesign --verify --deep --strict dist/netwatch-Darwin-*`.
2. Notarize with `xcrun notarytool submit <binary.zip> --keychain-profile <profile> --wait`; check the accepted result. A standalone CLI Mach-O cannot staple a ticket; use a signed/notarized distribution package if offline Gatekeeper acceptance is required. Never instruct users to disable Gatekeeper.
3. On Windows sign the executable using your code-signing certificate/hardware-backed signing service and `signtool sign`, then verify with `signtool verify /pa /all`.
4. After signing, recompute every corresponding `.sha256` (`hashlib.sha256`), upload replacements to the draft, inspect smoke tests on clean machines without Python, and publish the reviewed draft.

Signing certificates, Apple notarization credentials and a Windows signing identity are external prerequisites. None are provided by this repository. SHA-256 over HTTPS detects damaged downloads; it does not replace publisher signing. Current CI artifacts are unsigned and must be labelled accordingly.

After publication, `install-native.sh` / `install-native.ps1` detect the OS/architecture, verify the downloaded checksum, preserve previous executables and launch without Python. Set `NETWATCH_RELEASE=v4.0.0` to select a tag and `NETWATCH_ROLLBACK=1` to launch the previous locally installed native build. Installers never modify global PATH or system services. The source installer can select an older Git commit with `NETWATCH_REF=<SHA>` for source rollback.
