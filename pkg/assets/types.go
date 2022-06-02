// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assets

// Asset types used throughout the system.
const (
	BootableDisk       = "bootable_disk"
	NonBootableDisk    = "non_bootable_disk"
	KernelObject       = "kernel_object"
	VmLinux            = "vmlinux"
	HtmlCoverageReport = "html_coverage_report"
)

func GetHumanReadableName(assetType string) string {
	switch assetType {
	case BootableDisk:
		return "disk image"
	case NonBootableDisk:
		return "disk image (non-bootable)"
	case VmLinux:
		return "vmlinux file"
	case Kernelobject:
		return "kernel object"
	case HtmlCoverageReport:
		return "coverage report (html)"
	default:
		panic("invalid asset type: " + assetType)
	}
}
