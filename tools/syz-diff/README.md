# syz-diff

`syz-diff` fuzzes a kernel patch locally: it builds the base and the patched kernel and looks
for crashes that only happen on the patched one (similarly to [syz-cluster](/syz-cluster/README.md)).

## Usage

Build `syz-diff` in the syzkaller checkout and run it:

```bash
make diff
bin/syz-diff -workdir ~/syz-workdir -base-commit v6.18 -patch fix.diff -time 1h
```

* `-workdir` is a persistent directory that is reused between the runs. Kernel builds and
  downloads are cached there, so repeated runs with the same base commit and patch
  start fuzzing almost immediately.
* `-base-commit` is a commit hash, tag or branch of the
  [torvalds tree](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux).
* `-patch` is a git diff that applies to the base commit.
* `-time` is the fuzzing duration (default: `1h`). Press Ctrl+C to stop earlier.
* `-cache-size` limits the disk space used for the cached kernel builds and downloads
  (default: `100GB`). Each kernel build takes 1-2GB, the least recently used ones are removed first.

While fuzzing, the web UI is available at http://localhost:50544.

## Results

Every run creates a new session directory, which is printed at startup:

```
<workdir>/sessions/<YYYY-MM-DD_HH-MM-SS>/
├── log.txt          # syz-diff log
├── summary.txt      # found crashes and where to find their artifacts
├── build-*.log      # kernel build logs (only if the kernel was built in this run)
└── artifacts/
    ├── bugs.json    # all found crashes in a machine-readable form
    └── crashes/<id>/
        ├── patched_report, patched_crash_log
        ├── base_report  # if the base kernel also crashed
        ├── repro.prog   # if the crash was reproduced
        └── *.repro.log  # reproduction attempts
```

The crashes that are only observed on the patched kernel are listed at the top of `summary.txt`.

## Pre-built kernels

Alternatively, `syz-diff` can fuzz two already built kernels described by
[syz-manager configs](/docs/configuration.md):

```bash
bin/syz-diff -base base.cfg -new patched.cfg [-patch fix.diff]
```

If `-patch` is given, fuzzing is focused on the code modified by it. The findings are saved to
`crashes/` in the workdir of the `-new` config, and the web UI is served at its `http` address.
