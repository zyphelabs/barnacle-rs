# Releases with Knope

barnacle-rs uses Knope 0.22.4 and the same changeset-driven release model as baxe.
`knope.toml` versions `Cargo.toml` and the crate's entry in `Cargo.lock`, and writes
the release notes to `CHANGELOG.md`.

## One-time GitHub setup

Install the existing Zyphe release bot GitHub App on `zyphelabs/barnacle-rs`, with
Contents and Pull requests read/write permissions. Make these settings available to this
repository (repository settings, or organization settings with repository access):

- Variable `ZYPHE_RELEASE_BOT_APP_ID`.
- Secret `ZYPHE_RELEASE_BOT_APP_PRIVATE_KEY`.
- Secret `CRATES_TOKEN`, authorized to publish `barnacle-rs` on crates.io.

Release PRs are opened with the App token so that their CI runs. Local release preparation
and the ordinary PR checks need no credentials. The `ci` job matches the required `ci`
status check on `main`.

## Normal flow

1. Add a file under `.changeset/` with `knope document-change` alongside code changes.
2. PR CI runs formatting, `cargo check`, the tests against a Redis service, the release
   tool tests, Knope config validation, and a check that published code changes have a
   changeset.
3. After a push to `main` passes CI, Knope prepares the pending changesets: it bumps
   `Cargo.toml` and `Cargo.lock`, writes `CHANGELOG.md`, and deletes the consumed changesets.
4. CI opens or updates the PR from the `release` branch. Review its version and release
   notes. Further merges to `main` update the same release PR.
5. Merging that same-repository PR into `main` starts **Publish** on the exact merge
   commit. It reruns the tests, publishes the crate, then uses Knope to create the GitHub
   release and its tag (e.g. `v0.4.0`).

## Local verification

Install the pinned CLI with `cargo install knope --version 0.22.4 --locked`.

```sh
knope --dry-run prepare-release
python3 -B -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/check_changesets.py origin/main HEAD
```

To see the actual release diff, run `knope prepare-release` in a disposable checkout.
Unlike `--dry-run`, it consumes the changesets, updates files, and stages them. It does
not commit, tag, upload, or create a PR. Then `python3 scripts/publish.py` previews what
would be published.

## Retries and manual operation

Rerun a failed Publish workflow to retry its original merge commit. The publisher skips a
version already on crates.io, so a run that failed after uploading can still create the
GitHub release. Registry errors abort rather than being treated as a missing version.
The GitHub release is created only after publication.

The **ci** workflow can be dispatched on `main` to prepare a release without a new push.
**Publish** can be dispatched on `main` after a release is prepared; it refuses pending
changesets or a missing changelog entry for the current version. Prefer rerunning the
original workflow if `main` has advanced since the release merge.

No secrets or publishing steps run on unmerged PRs.
