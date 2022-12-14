// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"bytes"
	"testing"
)

func TestParseMaintainers(t *testing.T) {
	parsed, err := ParseLinuxMaintainers(bytes.NewReader(sampleMAINTAINERS))
	if err != nil {
		t.Fatal(err)
	}

	// Test full matching.
	results := parsed.Find(`include/net/cfg80211.h`)
	if len(results) != 1 || results[0].Name != `802.11 (including CFG80211/NL80211)` {
		t.Fatalf("unexpected results")
	}

}

const sampleMAINTAINERS = `
List of maintainers and how to submit kernel changes
====================================================

Please try to follow the guidelines below.  This will make things
easier on the maintainers.  Not all of these guidelines matter for every
trivial patch so apply some common sense.

Tips for patch submitters
-------------------------

1.	Always *test* your changes, however small, on at least 4 or
	5 people, preferably many more.

2.	< ... >

Descriptions of section entries and preferred order
---------------------------------------------------

	M: *Mail* patches to: FullName <address@domain>
	R: Designated *Reviewer*: FullName <address@domain>
	   These reviewers should be CCed on patches.
	L: *Mailing list* that is relevant to this area
	S: *Status*, one of the following:
	   Supported:	Someone is actually paid to look after this. < ... >
	W: *Web-page* with status/info
	Q: *Patchwork* web based patch tracking system site
	B: URI for where to file *bugs*. A web-page with detailed bug
	   filing info, a direct bug tracker link, or a mailto: URI.
	C: URI for *chat* protocol, server and channel where developers
	   usually hang out, for example irc://server/channel.
	P: Subsystem Profile document for more details submitting
	   patches to the given subsystem. This is either an in-tree file,
	   or a URI. See Documentation/maintainer/maintainer-entry-profile.rst
	   for details.
	T: *SCM* tree type and location.
	   Type is one of: git, hg, quilt, stgit, topgit
	F: *Files* and directories wildcard patterns.
	   A trailing slash includes all files and subdirectory files.
	   F:	drivers/net/	all files in and below drivers/net
	   F:	drivers/net/*	all files in drivers/net, but not below
	   F:	*/net/*		all files in "any top level directory"/net
	   One pattern per line.  Multiple F: lines acceptable.
	X: *Excluded* files and directories that are NOT maintained, same
	   rules as F:. Files exclusions are tested before file matches.
	   Can be useful for excluding a specific subdirectory, for instance:
	   F:	net/
	   X:	net/ipv6/
	   matches all files in and below net excluding net/ipv6/
	N: Files and directories *Regex* patterns.
	   N:	[^a-z]tegra	all files whose path contains tegra
	                        (not including files like integrator)
	   One pattern per line.  Multiple N: lines acceptable.
	   scripts/get_maintainer.pl has different behavior for files that
	   match F: pattern and matches of N: patterns.  By default,
	   get_maintainer will not look at git log history when an F: pattern
	   match occurs.  When an N: match occurs, git log history is used
	   to also notify the people that have git commit signatures.
	K: *Content regex* (perl extended) pattern match in a patch or file.
	   For instance:
	   K: of_get_profile
	      matches patches or files that contain "of_get_profile"
	   K: \b(printk|pr_(info|err))\b
	      matches patches or files that contain one or more of the words
	      printk, pr_info or pr_err
	   One regex pattern per line.  Multiple K: lines acceptable.

Maintainers List
----------------

.. note:: When reading this list, please look for the most precise areas
          first. When adding to this list, please keep the entries in
          alphabetical order.

802.11 (including CFG80211/NL80211)
M:	Johannes Berg <johannes@sipsolutions.net>
L:	linux-wireless@vger.kernel.org
S:	Maintained
W:	https://wireless.wiki.kernel.org/
Q:	https://patchwork.kernel.org/project/linux-wireless/list/
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless.git
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/wireless/wireless-next.git
F:	Documentation/driver-api/80211/cfg80211.rst
F:	Documentation/networking/regulatory.rst
F:	include/linux/ieee80211.h
F:	include/net/cfg80211.h
F:	include/net/ieee80211_radiotap.h
F:	include/net/iw_handler.h
F:	include/net/wext.h
F:	include/uapi/linux/nl80211.h
F:	include/uapi/linux/wireless.h
F:	net/wireless/

BROADCOM KONA GPIO DRIVER
M:	Ray Jui <rjui@broadcom.com>
R:	Broadcom internal kernel review list <bcm-kernel-feedback-list@broadcom.com>
S:	Supported
F:	Documentation/devicetree/bindings/gpio/brcm,kona-gpio.txt
F:	drivers/gpio/gpio-bcm-kona.c

PERFORMANCE EVENTS SUBSYSTEM
M:	Peter Zijlstra <peterz@infradead.org>
M:	Ingo Molnar <mingo@redhat.com>
M:	Arnaldo Carvalho de Melo <acme@kernel.org>
R:	Mark Rutland <mark.rutland@arm.com>
R:	Alexander Shishkin <alexander.shishkin@linux.intel.com>
R:	Jiri Olsa <jolsa@kernel.org>
R:	Namhyung Kim <namhyung@kernel.org>
L:	linux-perf-users@vger.kernel.org
L:	linux-kernel@vger.kernel.org
S:	Supported
W:	https://perf.wiki.kernel.org/
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git perf/core
F:	arch/*/events/*
F:	arch/*/events/*/*
F:	arch/*/include/asm/perf_event.h
F:	arch/*/kernel/*/*/perf_event*.c
F:	arch/*/kernel/*/perf_event*.c
F:	arch/*/kernel/perf_callchain.c
F:	arch/*/kernel/perf_event*.c
F:	include/linux/perf_event.h
F:	include/uapi/linux/perf_event.h
F:	kernel/events/*
F:	tools/lib/perf/
F:	tools/perf/

THE REST
M:	Linus Torvalds <torvalds@linux-foundation.org>
L:	linux-kernel@vger.kernel.org
S:	Buried alive in reporters
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
F:	*
F:	*/
`
