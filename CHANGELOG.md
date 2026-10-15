# Changelog

## Read this before creating a tag

**The tag is the version, and it is also the trigger.**

There is no version field to disagree with — `go.mod` has none — so a tag here
does two things at once: it names the release, and it starts the workflow that
builds, scans, attests and publishes to Harbor. There is no separate "publish"
step to forget, and no way to correct a number afterwards.

Two consequences that are specific to this repository:

- **Harbor tag immutability means one version can be released once.** The
  workflow pushes `X.Y.Z-amd64` and `X.Y.Z-arm64` before assembling `X.Y.Z`.
  If it fails after those land, re-running the same tag is refused — the
  per-architecture tags already exist. Bump the version instead. That is the
  correct answer anyway: a version that failed to release never existed.
- **The attestations are bound to the image digest.** Re-pushing an image
  changes its digest and invalidates the provenance and SBOM that were signed
  over the old one. Never re-push a released tag to "fix" it.

Before tagging:

1. **Read this file.** It records what has been released and what the next
   number is.
2. Confirm CI is green on the commit you are about to tag.
3. Tag with a `v` prefix: `v0.1.2`.
4. Push the tag. The workflow does the rest.
5. Confirm the result: the run is green, `X.Y.Z` appears in Harbor with both
   architectures, and the GitHub release carries the tarballs and the SBOM.
6. Add it to the table below.

## Released

| Version | Date | Digest | What it was |
|---|---|---|---|
| `v0.1.2` | 2026-10-15 | — | Follows panda-go to v0.5.4, so this service reports its own use. That release is where telemetry stopped being a call per operation and became a counter; because the counting lives inside the cipher rather than at each call site, moving the pin is the whole change and `internal/service` is untouched. What is collected is pinned in `panda-spec/telemetry-format.md` — three counters and the SDK version, on a window boundary, and no plaintext, ciphertext, key material or field values. **It reports nothing until it has a token**: the SDK reads `.panda/credentials` or `PANDA_PORTAL_TOKEN`, and a container has neither unless one is mounted or set. The constructor lost a parameter, so the call and seven test files drop an extra `nil`. |
| `v0.1.1` | 2026-10-13 | `sha256:220cb41d7642b770035511dc520f5c9b53c1dc0768166db747cbad1ffc14b9d9` | Blind index normalisation: the mode is now the caller's to choose, the default is `lowercase`, and an unrecognised mode is refused. Corrections to two things the OpenAPI document stated that were not true. Adds the Postman collection as a release asset. |
| `v0.1.0` | 2026-10-12 | `sha256:0588625ba4b81ee6e656abf04a0800b548ac331e3bc6e6221af7af5790acdde8` | First release. REST and gRPC, linux/amd64 and linux/arm64, build provenance and SBOM attested. |

## Notes for the next release

- `v0.1.0` predates the blind index fix and carries the defect described in
  `v0.1.1`. Any deployment still on `v0.1.0` should move.
- `v0.1.0`'s tags were pushed before Harbor tag immutability was enabled, so
  they are **not** protected. `v0.1.1` onwards should be. Worth confirming in
  the Harbor UI, which shows a lock on an immutable tag — the Harbor API
  reports the `immutable` flag as false for every tag here, including those
  pushed after the rule was enabled, and nobody has yet established which of
  the two to believe.
