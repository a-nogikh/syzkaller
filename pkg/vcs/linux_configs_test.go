// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
)

func TestLinuxReportConfigs(t *testing.T) {
	tests := []struct {
		name string
		typ  dashapi.CrashType
		test func(cf *kconfig.ConfigFile) bool
	}{
		{
			name: "warning",
			typ:  dashapi.Warning,
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "BUG")
			},
		},
		{
			name: "kasan bug",
			typ:  dashapi.KASAN,
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "KASAN")
			},
		},
		{
			name: "lockdep",
			typ:  dashapi.LockdepBug,
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "LOCKDEP")
			},
		},
		{
			name: "rcu stall",
			typ:  dashapi.Hang,
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "RCU_STALL_COMMON")
			},
		},
		{
			name: "unknown title",
			typ:  dashapi.UnknownCrash,
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "BUG", "KASAN", "LOCKDEP", "RCU_STALL_COMMON", "UBSAN", "DEBUG_ATOMIC_SLEEP")
			},
		},
	}

	const base = `
CONFIG_BUG=y
CONFIG_KASAN=y
CONFIG_LOCKDEP=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_UBSAN=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
`
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			conf, err := kconfig.ParseConfigData([]byte(base), "base")
			if err != nil {
				t.Fatal(err)
			}
			linuxConfigsForType(conf, test.typ, &debugtracer.NullTracer{})
			if !test.test(conf) {
				t.Fatal("invalid results")
			}
		})
	}
}

func onlySet(cf *kconfig.ConfigFile, names ...string) bool {
	for _, name := range names {
		if cf.Value(name) != kconfig.Yes {
			return false
		}
	}
	total := 0
	for _, param := range cf.Configs {
		if cf.Value(param.Name) == kconfig.Yes {
			total++
		}
	}
	return total == len(names)
}
