# Releasing

Releases are automated with [GoReleaser](https://goreleaser.com) via
`.github/workflows/release.yml`. Pushing a `vX.Y.Z` tag builds the binaries
(macOS + Linux, amd64 + arm64), publishes a GitHub release with checksums, and
updates the Homebrew tap formula.

## One-time setup

1. **Create the tap repo** `RevylAI/homebrew-tap` (public, empty is fine). This
   is what backs `brew install revylai/tap/greenlight`.
2. **Add a secret** `HOMEBREW_TAP_TOKEN` to this repo
   (Settings → Secrets and variables → Actions): a fine-grained or classic PAT
   with **contents: write** on `RevylAI/homebrew-tap`. The default `GITHUB_TOKEN`
   can't push to another repo, which is why this is needed.

## Cutting a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow does the rest. To dry-run locally first:

```bash
goreleaser release --snapshot --clean   # builds into ./dist, publishes nothing
goreleaser check                         # validate the config
```

After a release, both install paths work:

```bash
brew install revylai/tap/greenlight
go install github.com/RevylAI/greenlight/cmd/greenlight@latest
```
