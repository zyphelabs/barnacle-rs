# Changesets

Run `knope document-change` (Knope 0.22.4), or add a Markdown file here:

```markdown
---
default: patch
---

Describe the user-visible change in one sentence.

Add details below when needed.
```

The package is always called `default`, unquoted, followed by `patch`, `minor`, or
`major`. The first description line becomes a heading in the changelog, so keep it
short and complete.

Knope follows Cargo's pre-1.0 conventions: while the crate is 0.x, `major` bumps
0.3.x to 0.4.0 (a breaking change) and `minor` bumps 0.3.1 to 0.3.2. Use `patch` or
`minor` for anything that keeps existing code compiling and behaving the same.

Only these files drive version bumps; commit messages are ignored. Knope consumes
them into `CHANGELOG.md` when it prepares a release.

CI requires a changeset when a PR changes `src/` or the published parts of
`Cargo.toml`. Tests, examples, docs, workflow, and tooling changes do not need one, and
version-only release PRs are exempt.

See [the release workflow](releases.md) for setup and operation.

Keep documentation outside `.changeset/`: Knope treats every Markdown file there as a
change file, including `README.md`.
