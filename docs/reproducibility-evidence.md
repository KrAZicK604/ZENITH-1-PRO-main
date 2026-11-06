# Reproducibility evidence gate (v1)

This workflow produces an unsigned source-integrity inventory after the unit, static-security,
and dependency-audit gates succeed. It is not a signature, independent security audit,
scientific proof, or production authorization.

## Fields and limits

The manifest records the checked-out Git commit, SHA-256 for every tracked file
(including source, tests, dependency lockfile and workflow), CI event/run identifiers,
Python version, a UTC host-clock timestamp, and monotonic elapsed duration.
The timestamp is HOST_CLOCK_UNATTESTED. A manifest and its sidecar checksum
can both be replaced by an attacker controlling the runner.
GitHub artifact transport adds a SHA-256 digest but not an independent signature.

Generation fails closed for dirty tracked files, GITHUB_SHA mismatch, unsafe paths,
symlinks, empty or duplicate tracking lists, and existing evidence. Creation also
checks every tracked file against the committed Git blob, including files Git
status may hide through assume-unchanged or skip-worktree flags. Git
commands disable replacement-object interpretation with `--no-replace-objects`,
so the claimed commit resolves to its actual object tree rather than a locally
substituted view. This also applies when a custom replacement-ref namespace is
selected. They disable the repository-configurable core.fsmonitor hook, preventing
this Git command path from executing an untrusted filesystem-monitor program.
Other untrusted repository configuration and hostile runners remain separate
trust concerns; this is not a full Git sandbox.

The replacement-ref controls cover generation, verification of a rehashed
manifest and the direct committed-blob comparison. They do not authenticate
the Git executable, runner, working repository or an externally supplied commit.

Evidence *creation* is restricted to a nonsymlink path under the checked-out
repository's `.evidence/` directory, not merely somewhere inside the checkout.
This prevents writes into application, workflow, or Git administrative paths.
Both the manifest and its checksum path are checked for existing symlinks.
Existing manifest or checksum files
are never overwritten. Ordinary write exceptions remove only files created
by the attempt, preventing a stranded manifest after a sidecar-write error.
This pair is not a transaction across process crashes, power loss or hostile
concurrent directory replacement. A trusted, isolated runner remains necessary.
Verification fails closed for changed content, wrong checkout, missing files, altered
sidecar, and promotion/authority changes. The verifier also requires a clean
tracked worktree and compares every file's raw Git object ID with the blob in
the claimed HEAD commit. This rejects a forged manifest + freshly calculated
sidecar for modified checkout bytes, including a local index configured with
`assume-unchanged`. Git attribute filters or platform line-ending conversions
may require a byte-exact checkout; do not bypass this check to force a PASS.
The Git commit itself must still be authenticated against a trusted external
reference: a mutable Git repository is not a provenance authority. The evidence format remains PAPER_ONLY,
PROMOTION_BLOCKED with production authority NONE.

## Independent offline check

### Manifest input bounds

Verification reads regular files only: at most 1,000,000 manifest bytes and
4,096 checksum bytes. Oversized files, special files and leaf symlinks are
rejected. Descriptor checks and a capped read enforce the size/type limits even
across replacement or growth. Device, inode, mode, size, modification time and
change time must also match before opening, after reading and at the final path
check; bytes read must equal the recorded size. These checks reject observable
file replacement and in-place changes. Access time is excluded because reading
can legitimately change it. Nonblocking open is used
where supported so a raced-in POSIX FIFO cannot stall the descriptor check.
These checks are not a transaction across the manifest and sidecar, cannot
prevent changes after the final check, and do not defeat a hostile host able to
forge filesystem identity or metadata. Parent-directory races still require
external isolation.

Manifest JSON must be UTF-8, with nesting depth at most 16, no duplicate object
members, no nonfinite numeric values and no integer token longer than 128
characters. Escaped quotes and delimiters inside strings do not count as
structural nesting. Schema version and file count must be actual integers,
not booleans. The file list is capped at 4,096 entries. Generation refuses to
publish evidence beyond the same size/file-count limits; valid generated
evidence retains its existing serialization and checksum format.

These are bounded-input controls, not a total CPU/memory sandbox for the Git
checkout, Git subprocesses or source-file hashing. The limits require a
separately reviewed adjustment if repository growth exceeds them. They do not
authenticate a runner, authorize promotion or replace independent review.

### Running the verifier

Metadata is validated before the Git comparison: timestamps use the generator's
canonical `YYYY-MM-DDTHH:MM:SSZ` form and a valid calendar date, elapsed duration
is a nonnegative integer (not a boolean), and Python version has three numeric
components. The CI context must contain exactly the five generated string
fields. A nonempty context SHA must equal the manifest commit; nonempty run IDs
and attempts must be positive ASCII decimal strings. Empty context values remain
permitted for local records. Generation applies the same metadata checks before
writing a record.

These are syntax/consistency checks only. A well-formed invented timestamp,
duration, Python version or CI origin can still pass unsigned verification when
the source bytes match. The trusted-main signing gate separately checks actual
workflow context, and signature policy is a separate consumer verification step.
No host clock, elapsed measurement, Python-runtime claim or sender is thereby
authenticated. Malformed metadata produces an explicit CLI failure.

Check out the manifest's exact git_head (on PRs this may be a generated merge
commit rather than the branch tip). Download both files from the GitHub
repro-evidence artifact into .evidence/ and run:

    python scripts/repro_evidence.py verify

A passing check reports EVIDENCE_VERIFIED, the exact commit and file count.

For a local trial in a clean Git working tree:

    python scripts/repro_evidence.py create
    python scripts/repro_evidence.py verify

The generator intentionally refuses to overwrite an existing manifest.
Archive evidence separately before repeating the experiment.

## What this does NOT establish

This does not authenticate the origin of results, guarantee a trusted clock,
prove that tests are scientifically adequate, or establish operational
readiness. Independent reviewer identity, signed attestations, calibrated
false-acceptance rates, and external scientific validation are separate gates.
