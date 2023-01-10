// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"testing"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/stretchr/testify/assert"
)

func TestPathMatcher(t *testing.T) {
	m := MakePathMatcher()
	first := "arm"
	m.Register(first,
		entity.PathRule{
			IncludeRegexp: `^arch/arm/.*$`,
			ExcludeRegexp: `^arch/arm/boot/dts/.*$`,
		},
		entity.PathRule{IncludeRegexp: `^drivers/spi/spi-pl022\.c$`},
		entity.PathRule{
			IncludeRegexp: `^drivers/irqchip/irq-vic\.c$|^Documentation/devicetree/bindings/interrupt-controller/arm,vic\.yaml$`,
		},
	)
	second := "docs"
	m.Register(second, entity.PathRule{IncludeRegexp: `^Documentation/.*$`})

	assert.ElementsMatch(t, []interface{}{first, second},
		m.Match(`Documentation/devicetree/bindings/interrupt-controller/arm,vic.yaml`))
	assert.ElementsMatch(t, []interface{}{first}, m.Match(`arch/arm/a.c`))
	assert.ElementsMatch(t, []interface{}{second}, m.Match(`Documentation/a/b/c.md`))
	assert.ElementsMatch(t, []interface{}{}, m.Match(`arch/boot/dts/a.c`))
}

func TestPathMatchOrder(t *testing.T) {
	m := MakePathMatcher()
	m.Register("name", entity.PathRule{
		IncludeRegexp: `^a/b/.*$`,
		ExcludeRegexp: `^a/.*$`,
	})
	// If we first exclude a/, then a/b/c never matches.
	assert.ElementsMatch(t, []interface{}{}, m.Match("a/b/c"))
}

func TestPathMatchValidation(t *testing.T) {
	m := MakePathMatcher()
	assert.Error(t, m.Register("name", entity.PathRule{
		IncludeRegexp: `^abcd(`,
	}))
	assert.Error(t, m.Register("name", entity.PathRule{
		ExcludeRegexp: `^abcd(`,
	}))
}
