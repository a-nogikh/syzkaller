// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type Seeds struct {
	CorpusDB   *db.DB
	Fresh      bool
	Candidates []fuzzer.Candidate
}

const CurrentDBVersion = 5

func LoadSeeds(cfg *mgrconfig.Config, immutable bool) Seeds {
	var info Seeds
	var err error
	info.CorpusDB, err = db.Open(filepath.Join(cfg.Workdir, "corpus.db"), !immutable)
	if err != nil {
		if info.CorpusDB == nil {
			log.Fatalf("failed to open corpus database: %v", err)
		}
		log.Errorf("read %v inputs from corpus and got error: %v", len(info.CorpusDB.Records), err)
	}
	info.Fresh = len(info.CorpusDB.Records) == 0
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	corpusFlags := fuzzer.ProgFromCorpus | fuzzer.ProgMinimized | fuzzer.ProgSmashed
	switch info.CorpusDB.Version {
	case 0:
		// Version 0 had broken minimization, so we need to re-minimize.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 1:
		// Version 1->2: memory is preallocated so lots of mmaps become unnecessary.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 2:
		// Version 2->3: big-endian hints.
		corpusFlags &= ^fuzzer.ProgSmashed
		fallthrough
	case 3:
		// Version 3->4: to shake things up.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 4:
		// Version 4->5: fix for comparison argument sign extension.
		// Introduced in 1ba0279d74a35e96e81de87073212d2b20256e8f.

		// Update (July 2024):
		// We used to reset the fuzzer.ProgSmashed flag here, but it has led to
		// perpetual corpus retriage on slow syzkaller instances. By now, all faster
		// instances must have already bumped their corpus versions, so let's just
		// increase the version to let all others go past the corpus triage stage.
		fallthrough
	case CurrentDBVersion:
	}
	type Input struct {
		IsSeed bool
		Key    string
		Data   []byte
		Prog   *prog.Prog
	}
	procs := runtime.GOMAXPROCS(0)
	inputs := make(chan *Input, procs)
	outputs := make(chan *Input, procs)
	var wg sync.WaitGroup
	wg.Add(procs)
	for p := 0; p < procs; p++ {
		go func() {
			defer wg.Done()
			for inp := range inputs {
				inp.Prog, _ = LoadProg(cfg.Target, inp.Data)
				outputs <- inp
			}
		}()
	}
	go func() {
		wg.Wait()
		close(outputs)
	}()
	go func() {
		for key, rec := range info.CorpusDB.Records {
			inputs <- &Input{
				Key:  key,
				Data: rec.Val,
			}
		}
		seedDir := filepath.Join(cfg.Syzkaller, "sys", cfg.TargetOS, "test")
		if osutil.IsExist(seedDir) {
			seeds, err := os.ReadDir(seedDir)
			if err != nil {
				log.Fatalf("failed to read seeds dir: %v", err)
			}
			for _, seed := range seeds {
				data, err := os.ReadFile(filepath.Join(seedDir, seed.Name()))
				if err != nil {
					log.Fatalf("failed to read seed %v: %v", seed.Name(), err)
				}
				inputs <- &Input{
					IsSeed: true,
					Data:   data,
				}
			}
		}
		close(inputs)
	}()
	brokenSeeds := 0
	var brokenCorpus []string
	var candidates []fuzzer.Candidate
	for inp := range outputs {
		if inp.Prog == nil {
			if inp.IsSeed {
				brokenSeeds++
			} else {
				brokenCorpus = append(brokenCorpus, inp.Key)
			}
			continue
		}
		flags := corpusFlags
		if inp.IsSeed {
			if _, ok := info.CorpusDB.Records[hash.String(inp.Prog.Serialize())]; ok {
				continue
			}
			// Seeds are not considered "from corpus" (won't be rerun multiple times)
			// b/c they are tried on every start anyway.
			flags = fuzzer.ProgMinimized
		}
		candidates = append(candidates, fuzzer.Candidate{
			Prog:  inp.Prog,
			Flags: flags,
		})
	}
	if len(brokenCorpus)+brokenSeeds != 0 {
		log.Logf(0, "broken programs in the corpus: %v, broken seeds: %v", len(brokenCorpus), brokenSeeds)
	}
	if !immutable {
		// This needs to be done outside of the loop above to not race with corpusDB reads.
		for _, sig := range brokenCorpus {
			info.CorpusDB.Delete(sig)
		}
		if err := info.CorpusDB.Flush(); err != nil {
			log.Fatalf("failed to save corpus database: %v", err)
		}
	}
	// Switch database to the mode when it does not keep records in memory.
	// We don't need them anymore and they consume lots of memory.
	info.CorpusDB.DiscardData()
	info.Candidates = candidates
	return info
}

func LoadProg(target *prog.Target, data []byte) (*prog.Prog, error) {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return nil, err
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil, fmt.Errorf("longer than %d calls", prog.MaxCalls)
	}
	// For some yet unknown reasons, programs with fail_nth > 0 may sneak in. Ignore them.
	for _, call := range p.Calls {
		if call.Props.FailNth > 0 {
			return nil, fmt.Errorf("input has fail_nth > 0")
		}
	}
	return p, nil
}

type FilteredCandidates struct {
	Candidates     []fuzzer.Candidate
	ModifiedHashes []string
	SeedCount      int
}

func FilterCandidates(candidates []fuzzer.Candidate, syscalls map[*prog.Syscall]bool) FilteredCandidates {
	var ret FilteredCandidates
	for _, item := range candidates {
		if !item.Prog.OnlyContains(syscalls) {
			ret.ModifiedHashes = append(ret.ModifiedHashes, hash.String(item.Prog.Serialize()))
			// We cut out the disabled syscalls and retriage/minimize what remains from the prog.
			// The original prog will be deleted from the corpus.
			item.Flags &= ^fuzzer.ProgMinimized
			item.Prog.FilterInplace(syscalls)
			if len(item.Prog.Calls) == 0 {
				continue
			}
		}
		if item.Flags&fuzzer.ProgFromCorpus == 0 {
			ret.SeedCount++
		}
		ret.Candidates = append(ret.Candidates, item)
	}
	return ret
}
