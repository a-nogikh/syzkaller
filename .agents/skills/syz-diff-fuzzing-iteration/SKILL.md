---
name: syz-diff-fuzzing-iteration
description: >-
  Iterate on syzkaller's fuzzing engine or patch-focused fuzzing (focus areas, fuzz targets,
  syscall selection, corpus handling) by repeatedly rebuilding and running tools/syz-diff
  against a fixed kernel patch with a reused cache, then comparing the session logs and stats.
  Use when evaluating whether a fuzzer/focus change helps to reach or crash the patched code.
---

# Iterating on Fuzzing with `syz-diff`

First, read the [syz-diff README](../../../tools/syz-diff/README.md) for how to build and run it and
where the results of each session are stored.

Kernel builds, the image and the corpus are cached in `-workdir` and **do not depend on the syzkaller
revision**, so after the first run every iteration on syzkaller itself goes straight to fuzzing.
Use this to evaluate changes to e.g.:

* the fuzzing engine: `pkg/fuzzer/`, `pkg/corpus/`, `prog/`;
* patch-focused fuzzing: `pkg/manager/diff/` (e.g. `PatchFocusAreas`), `syz-cluster/pkg/fuzz/`;
* per-subsystem syscall/VM settings: `syz-cluster/pkg/fuzzconfig/`;
* fuzz target routing (focus, corpus, kernel config per patch): `syz-cluster/pkg/api/fuzz_targets.yaml`.

## 1. Keep the experiment inputs fixed

Keep everything except the syzkaller change constant between iterations:

* **One `-workdir`.** Never delete its `cache/`, `linux/` or `build-repo/` between iterations —
  that's what makes iterations fast. Never edit files in `build-repo/` by hand.
* **The same `-base-commit` (full hash) and the same `-patch` file.** Keep the patch outside the
  workdir; any edit of the patch file means a new patched kernel build.
* **Only one `syz-diff` at a time per workdir.**
* **The same `-time`** for the runs you compare.
* The cached corpus is refreshed once per ISO week. Compare runs from the same week, or note the
  corpus change when comparing across the week boundary.

To pick a realistic patch, take a fuzzed series from https://ci.syzbot.org: the series page shows the
base commit (`Build Base` row) and the patch is available at
`https://ci.syzbot.org/series/<id>/all_patches`. If the base commit isn't in the torvalds tree,
fetch it once with `git -C <workdir>/linux fetch <tree-url> <commit>`.

## 2. The iteration loop

1. Make the syzkaller change and rebuild with `make diff`.
2. Rerun `syz-diff` with exactly the same flags as before, always with `-repro=false`.
3. Analyze the new session (section 3) and compare it with the previous ones.

Record which syzkaller change each session corresponds to (e.g. `git rev-parse HEAD` and a one-line
description next to the session dir name) — the session does not record it itself.

### Disable reproduction

**Always use `-repro=false` when iterating on fuzzing.** Crash reproduction takes VMs away from
fuzzing for long periods and then spends more time verifying the reproducer on the base kernel.
Without it, all VMs keep fuzzing for the whole session, so you get more signal (coverage, corpus
growth, crashes) in a shorter time. Crashes are still recorded; check whether a target bug was found
by its title (see below). Only enable reproduction when you specifically need reproducers.

### How long to run

The session starts with **corpus triage**: all programs of the downloaded corpus are re-executed
on the patched kernel. Fuzzing results before triage completes are not meaningful.

* Triage is complete once the `candidates` stat drops to 0 (see the stats below); the log also
  prints `triaged 99.x% of the corpus` around that moment. It takes from tens of minutes to more
  than an hour, depending on the corpus.
* **Run for at least 1 hour after corpus triage has completed.** On the first run with a new
  patch/corpus, measure the triage duration from the stats and set `-time` to
  `<triage duration> + 1h` or more for all subsequent runs. If unsure, start with `-time 3h`.
* `-time` can't be extended for a running session. To stop earlier, send SIGINT (Ctrl+C, or
  `kill -INT <pid>`): the summary is still written. Don't `kill -9` it.
* The session may stop early on its own: if the fuzzer has not reached the modified code within
  30 minutes after triage, the log says `fuzzer has not reached the modified code in 30m0s,
  aborting` (unless the fuzz target sets `skip_cover_check`). For focus-related changes this is an
  important (negative) result by itself.

When running `syz-diff` from an agent, start it as a background task with a notification timeout
longer than `-time` (plus build time on the first run), and only check the log periodically
(e.g. every 15–30 minutes) instead of polling.

## 3. Analyzing a session

### Stats over time

Every 5 minutes, the session's `log.txt` contains a `STAT {...}` JSON dump with the patched
instance's fuzzer stats. Extract them as a table with the helper script:

```bash
python3 .agents/skills/syz-diff-fuzzing-iteration/scripts/stat_series.py \
  <workdir>/sessions/<session1>/log.txt <workdir>/sessions/<session2>/log.txt
# List all available stat names:
python3 .agents/skills/syz-diff-fuzzing-iteration/scripts/stat_series.py <log.txt> --list
# Select specific stats:
python3 .agents/skills/syz-diff-fuzzing-iteration/scripts/stat_series.py <log.txt> \
  -k 'candidates,corpus,corpus [symbols],corpus [files],coverage'
```

The most useful stats:

* `candidates` — corpus triage queue; triage is done when it reaches 0.
* `corpus [symbols]`, `corpus [files]` — programs in the corpus that reach the functions/files
  modified by the patch (the focus areas). **This is the main metric for focus-related changes.**
* `coverage`, `signal`, `corpus` — overall coverage and corpus size.
* `exec total [new]`, `exec total [base]` — executions on the patched/base kernels; a drop in the
  execution rate means the change made fuzzing slower.

Compare the stats at the same time offsets **after triage completion**, not at absolute times,
since triage duration varies between runs.

### Useful log lines

```bash
cd <workdir>/sessions/<session>
grep -E "area .*PCs in the cover filter|executor cover filter" log.txt  # focus area sizes
grep -E "reached the focused areas|not reached the modified code" log.txt
grep "patched crashed:" log.txt          # every crash on the patched kernel, with title
grep -E "boot error|machine check" log.txt
```

To check whether a specific (target) bug was found across iterations:

```bash
grep -H "<bug title substring>" <workdir>/sessions/*/summary.txt
```

### Drawing conclusions

* Fuzzing is randomized. Differences of a few percent between single runs are noise; for small
  effects, repeat each variant (2–3 runs) and compare the ranges.
* Always compare against a baseline run with unmodified syzkaller made with the same inputs and
  `-time` (and ideally in the same week, because of the corpus refresh).
* Report the results as a small table: variant, session dir, triage duration, focus-area corpus
  size and coverage at triage+1h (and at the end), found crash titles.

## 4. Housekeeping

* Each session keeps the manager workdirs (`base/`, `patched/`) with a copy of the corpus. Delete
  old sessions you no longer need (`rm -rf <workdir>/sessions/<old-session>`); this never affects
  the cache.
* With a small `-cache-size`, least recently used kernel builds may get evicted, so an old
  base/patch combination may need a rebuild later.
