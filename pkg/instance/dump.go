package instance

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

func ExtractMemoryDump(inst *vm.Instance, target *targets.Target, path string) error {
	const (
		maxRetries = 10
		retrySleep = 30 * time.Second
		cmd        = "/usr/sbin/makedumpfile -F -c -d 9 /proc/vmcore"
	)
	if target.OS != targets.Linux {
		return fmt.Errorf("memory dump is only supported on linux")
	}

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		log.Logf(0, "trying to extract memory dump (attempt %v/%v)", i+1, maxRetries)
		err := extractKdumpInner(inst, path, cmd)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Logf(0, "failed to extract memory dump: %v", err)
		time.Sleep(retrySleep)
	}
	return fmt.Errorf("failed to extract memory dump after %v attempts: %w", maxRetries, lastErr)
}

func extractKdumpInner(inst *vm.Instance, path, cmd string) error {
	// We need a long timeout for dump extraction, it can be gigabytes.
	// 1 hour should be enough for typical scenarios.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	outc, errc, err := inst.RunStream(ctx, cmd)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create dump file: %w", err)
	}
	defer f.Close()

	for {
		select {
		case out, ok := <-outc:
			if !ok {
				outc = nil
				continue
			}
			if _, err := f.Write(out); err != nil {
				return fmt.Errorf("failed to write to dump file: %w", err)
			}
		case err := <-errc:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
