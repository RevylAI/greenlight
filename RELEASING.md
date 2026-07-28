# Releasing

Releases are automated with [GoReleaser](https://goreleaser.com) via
`.github/workflows/release.yml`. Pushing a `vX.Y.Z` tag builds the binaries
(macOS + Linux, amd64 + arm64) and publishes a GitHub release with checksums.

## Cutting a release

```bash
git tag -a v0.2.0 -m "v0.2.0 — what changed"
git push origin v0.2.0
```

Bump `version` in `metadata.json` and `.claude-plugin/plugin.json` first, in a
normal PR. The tag should point at a commit where those already read the new
number.

To dry-run locally:

```bash
goreleaser check                        # validate the config
goreleaser release --snapshot --clean   # builds into ./dist, publishes nothing
```

After a release, both install paths work:

```bash
brew install revylai/tap/greenlight
go install github.com/RevylAI/greenlight/cmd/greenlight@latest
```

## How the Homebrew tap is updated

`brew install revylai/tap/greenlight` is backed by
[`RevylAI/homebrew-tap`](https://github.com/RevylAI/homebrew-tap).

The `homebrew_casks` block in `.goreleaser.yml` wants to push the cask there
during the release, which needs a `HOMEBREW_TAP_TOKEN` secret, because a
workflow's built-in `GITHUB_TOKEN` cannot write to a different repository. That
secret has never been set, and creating it needs **admin** on this repo. The
v0.2.0 release published its binaries fine and then failed on that step with
`401 Bad credentials`.

So the tap updates itself instead. `.github/workflows/update-cask.yml` in the
tap repo polls this repo's releases hourly, regenerates `Casks/greenlight.rb`,
and commits with its own `GITHUB_TOKEN`. Reading a public repo's releases needs
no credentials and a workflow can always write to its own repo, so that path
needs no secret and no admin. It can also be run on demand from the tap's
Actions tab if you don't want to wait for the next hour.

Nothing needs to be done during a release. Confirm the tap picked it up:

```bash
brew update && brew info --cask revylai/tap/greenlight
```

If `HOMEBREW_TAP_TOKEN` is ever configured, both paths can coexist: the tap
workflow generates output byte-identical to GoReleaser's template, so whichever
runs second is a no-op rather than a revert.

### Gotchas worth knowing

- **The tap serves a cask, not a formula.** GoReleaser's `brews` output is
  deprecated and now fails `goreleaser check`. Homebrew prefers a formula over a
  cask of the same name, so a leftover `Formula/greenlight.rb` will silently keep
  winning and serving an old version. There must only be one.
- **Don't hash locally built archives.** The builds are not byte-reproducible, so
  a cask generated from a local `goreleaser release --snapshot` carries hashes
  that do not match the published artifacts, and every install fails checksum
  verification. Always take hashes from the release's `checksums.txt`.
- **GoReleaser infers the repo from the git remote.** Running a dry-run on a
  fork bakes the fork's download URLs into the generated cask. `.goreleaser.yml`
  pins `release.github` to `RevylAI/greenlight` to prevent that.
