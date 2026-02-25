# checkout-index - Reproducer for CVE-2025-22620

This is the proof of concept code for [RUSTSEC-2025-0001](https://rustsec.org/advisories/RUSTSEC-2025-0001.html) (CVE-2025-22620, [GHSA-fqmf-w4xh-33rh](https://github.com/GitoxideLabs/gitoxide/security/advisories/GHSA-fqmf-w4xh-33rh). It is the same code as in the advisory, but in the form of a Rust project, with `Cargo.toml` and `Cargo.lock` included.

This repo was useful while writing the advisory, and I figured it might occasionally be useful to others. However, I expect this to be of much less interest than the advisory, and also this is not a substitute for the information in the advisory. As noted in the advisory, the vulnerability is fixed in `gix-worktree-state` 0.17.0.

## Branches

- The `main` branch has the version of the code presented in step 2 of the advisory.
- The `unaffected-case` branch has the modification described in step 7 to show the effect of explicitly setting `destination_is_initially_empty: true`.
- The `patched-version` branch uses updated dependencies, including version 0.17.0 of its transitive `gix-worktree-state` dependency. This is to show that the vulnerability has been fixed (and what the non-vulnerable behavior looks like).

The `main` and `unaffected-case` branches deliberately use vulnerable dependency versions, in order demonstrate significant cases where vulnerable behavior is and is not observed, when a vulnerable version of `gix-worktree-state` is used.

## License

[**CC0-1.0**](COPYING), same as [the RUSTSEC advisory](https://rustsec.org/advisories/RUSTSEC-2025-0001.html).
