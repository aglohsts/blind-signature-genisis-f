# third_party

## lazer

The LaZer lattice zero-knowledge library, which supplies both NIZK proof
systems of the construction. Upstream is
<https://github.com/lazer-crypto/lazer>.

This is the tracked content of one pinned revision, taken with
`git archive`, so it holds no build output and no repository metadata:

| | |
|---|---|
| `lazer` | `2fa3dfb1de7cf5d7f70ed34dd101d8863c624cfe` |
| `lazer/src/labrados` (a submodule upstream) | `3f95485139ffaa65fe572da809b90772901372e5` |

The revision is pinned because later ones may change the generated proof
profiles, and the relation encodings in `src/signature/lazer_statement.rs`
depend on the dimensions those profiles fix.

### What was removed, and what was not

Three files of git housekeeping are left out: the two `.gitignore`
files, which describe build output that is not present in a snapshot,
and `.gitmodules`, which would say that `lazer/src/labrados` has to be
fetched when its content is already here. Nothing else is changed, and
no source file is.

The two defects described in the report are corrected by
`../lazer/patches/*.patch`, which `build.rs` applies to a copy of this
directory at build time. They are kept as patches, and this copy is kept
pristine, so that what was changed can be read in two short files rather
than searched for in 5 MB of source.

### Licences

LaZer is MIT, Copyright (c) 2022-2026 IBM: `lazer/LICENSE`.
Labrador is MIT: `lazer/src/labrados/LICENSE`.
Both permit redistribution provided the notices travel with the code,
which is why they are included here.

`lazer/third_party` carries two further dependencies as zip archives,
unpacked during the build: Intel HEXL (Apache-2.0) and the Falcon
reference implementation (MIT).
