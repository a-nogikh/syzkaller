// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
)

type addBuildCallback func(req *dashapi.AddBuildAssetReq) error

type dashMock struct {
	downloadURLs  map[string]bool
	addBuildAsset addBuildCallback
}

func newDashMock() *dashMock {
	return &dashMock{downloadURLs: map[string]bool{}}
}

func (dm *dashMock) do(method string, req, mockReply interface{}) error {
	switch method {
	case "add_build_asset":
		addBuildAsset := req.(*dashapi.AddBuildAssetReq)
		if dm.addBuildAsset != nil {
			if err := dm.addBuildAsset(addBuildAsset); err != nil {
				return nil
			}
		}
		dm.downloadURLs[addBuildAsset.DownloadURL] = true
		return nil
	case "needed_assets":
		resp := mockReply.(*dashapi.NeededAssetsResp)
		for url := range dm.downloadURLs {
			resp.DownloadURLs = append(resp.DownloadURLs, url)
		}
		return nil
	}
	return nil
}

func (dm *dashMock) getDashapi() *dashapi.Dashboard {
	return dashapi.NewMock(dm.do)
}

func makeStorage(dash *dashapi.Dashboard) (*Storage, *testStorageBackend) {
	be := makeTestStorageBackend()
	cfg := &Config{
		UploadTo: "test://test",
		Assets: map[Type]TypeConfig{
			KernelObject:       {Always: true},
			KernelImage:        {Always: true},
			HTMLCoverageReport: {Always: true},
		},
	}
	tracer := debugtracer.DebugTracer(&debugtracer.NullTracer{})
	if testing.Verbose() {
		tracer = &debugtracer.GenericTracer{
			WithTime:    true,
			TraceWriter: os.Stdout,
		}
	}
	return &Storage{
		dash:          dash,
		cfg:           cfg,
		backend:       be,
		tracer:        tracer,
		preprocessors: DefaultPreprocessors(),
	}, be
}

func validateGzipContent(req *uploadRequest, expected []byte) error {
	reader, err := gzip.NewReader(req.reader)
	if err != nil {
		return fmt.Errorf("gzip.NewReader failed: %w", err)
	}
	defer reader.Close()
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read of ungzipped content failed: %w", err)
	}
	if !reflect.DeepEqual(body, expected) {
		return fmt.Errorf("decompressed: %#v, expected: %#v", body, expected)
	}
	return nil
}

func validateXzContent(req *uploadRequest, expected []byte) error {
	xzAvailable := PreprocessXz.Available()
	xzUsed := strings.HasSuffix(req.savePath, ".xz")
	if xzAvailable && !xzUsed {
		return fmt.Errorf("xz was available, but didn't get used")
	}
	if xzUsed {
		cmd := osutil.Command("xz", "--decompress", "--to-stdout")
		cmd.Stdin = req.reader
		out, err := osutil.Run(time.Minute, cmd)
		if err != nil {
			return fmt.Errorf("xz invocation failed: %w", err)
		}
		if !reflect.DeepEqual(out, expected) {
			return fmt.Errorf("decompressed: %#v, expected: %#v", out, expected)
		}
		return nil
	}
	return validateGzipContent(req, expected)
}

func TestUploadBuildAsset(t *testing.T) {
	dashMock := newDashMock()
	storage, be := makeStorage(dashMock.getDashapi())
	be.currentTime = time.Now().Add(-2 * deletionEmbargo)
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}

	// Upload two assets using different means.
	vmLinuxContent := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	dashMock.addBuildAsset = func(req *dashapi.AddBuildAssetReq) error {
		if req.AssetType != string(KernelObject) {
			t.Fatalf("expected KernelObject, got %v", req.AssetType)
		}
		if !strings.Contains(req.DownloadURL, "vmlinux") {
			t.Fatalf("%#v was expected to mention vmlinux", req.DownloadURL)
		}
		return nil
	}
	be.objectUpload = func(req *uploadRequest) error {
		err := validateXzContent(req, vmLinuxContent)
		if err != nil {
			t.Fatalf("file content verification for vmlinux failed: %s", err)
		}
		return nil
	}
	err := storage.UploadBuildAsset(bytes.NewReader(vmLinuxContent), "vmlinux", KernelObject, build)
	if err != nil {
		t.Errorf("UploadBuildAssetCopy failed: %s", err)
	}

	// Upload the same file the second time.
	storage.UploadBuildAsset(bytes.NewReader(vmLinuxContent), "vmlinux", KernelObject, build)
	// The currently expected behavior is that it will be uploaded twice and will have
	// different names.
	if len(dashMock.downloadURLs) < 2 {
		t.Fatalf("same-file upload was expected to succeed, but it didn't; %#v", dashMock.downloadURLs)
	}

	diskImageContent := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
	dashMock.addBuildAsset = func(req *dashapi.AddBuildAssetReq) error {
		if req.AssetType != string(KernelImage) {
			t.Fatalf("expected KernelImage, got %v", req.AssetType)
		}
		if !strings.Contains(req.DownloadURL, "disk") ||
			!strings.Contains(req.DownloadURL, ".img") {
			t.Fatalf("%#v was expected to mention disk.img", req.DownloadURL)
		}
		if !strings.Contains(req.DownloadURL, build.KernelCommit) {
			t.Fatalf("%#v was expected to mention build commit", req.DownloadURL)
		}
		return nil
	}
	be.objectUpload = func(req *uploadRequest) error {
		err := validateXzContent(req, diskImageContent)
		if err != nil {
			t.Fatalf("file content verification for disk.raw failed: %s", err)
		}
		return nil
	}
	storage.UploadBuildAsset(bytes.NewReader(diskImageContent), "disk.img", KernelImage, build)

	// First try to remove two assets.
	allUrls := []string{}
	for url := range dashMock.downloadURLs {
		allUrls = append(allUrls, url)
	}
	if len(allUrls) != 3 {
		t.Fatalf("invalid dashMock state: expected 3 assets, got %d", len(allUrls))
	}
	dashMock.downloadURLs = map[string]bool{allUrls[2]: true, "http://non-related-asset.com": true}

	// Pretend there's an asset deletion error.
	be.objectRemove = func(string) error { return fmt.Errorf("not now") }
	err = storage.DeprecateAssets()
	if err == nil {
		t.Fatalf("DeprecateAssets() should have failed")
	}

	// Let the deletion be successful.
	be.objectRemove = nil
	err = storage.DeprecateAssets()
	if err != nil {
		t.Fatalf("DeprecateAssets() was expected to be successful, got %s", err)
	}
	err = be.hasOnly([]string{allUrls[2]})
	if err != nil {
		t.Fatalf("after first DeprecateAssets(): %s", err)
	}

	// Delete the rest.
	dashMock.downloadURLs = map[string]bool{}
	err = storage.DeprecateAssets()
	if err != nil || len(be.objects) != 0 {
		t.Fatalf("second DeprecateAssets() failed: %s, len %d",
			err, len(be.objects))
	}
}

func TestUploadHtmlAsset(t *testing.T) {
	dashMock := newDashMock()
	storage, be := makeStorage(dashMock.getDashapi())
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}
	htmlContent := []byte("<html><head><title>Hi!</title></head></html>")
	dashMock.addBuildAsset = func(req *dashapi.AddBuildAssetReq) error {
		if req.AssetType != string(HTMLCoverageReport) {
			t.Fatalf("expected HtmlCoverageReport, got %v", req.AssetType)
		}
		if !strings.Contains(req.DownloadURL, "cover_report") {
			t.Fatalf("%#v was expected to mention cover_report", req.DownloadURL)
		}
		if !strings.HasSuffix(req.DownloadURL, ".html") {
			t.Fatalf("%#v was expected to have .html extension", req.DownloadURL)
		}
		return nil
	}
	be.objectUpload = func(req *uploadRequest) error {
		err := validateGzipContent(req, htmlContent)
		if err != nil {
			t.Fatalf("file content verification for cover_report.html failed: %s", err)
		}
		return nil
	}
	storage.UploadBuildAsset(bytes.NewReader(htmlContent), "cover_report.html",
		HTMLCoverageReport, build)
}

func TestRecentAssetDeletionProtection(t *testing.T) {
	dashMock := newDashMock()
	storage, be := makeStorage(dashMock.getDashapi())
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}
	htmlContent := []byte("<html><head><title>Hi!</title></head></html>")
	be.currentTime = time.Now().Add(-time.Hour * 24 * 6)
	err := storage.UploadBuildAsset(bytes.NewReader(htmlContent), "cover_report.html",
		HTMLCoverageReport, build)
	if err != nil {
		t.Fatalf("failed to upload a file: %v", err)
	}

	// Try to delete a recent file.
	dashMock.downloadURLs = map[string]bool{}
	err = storage.DeprecateAssets()
	if err != nil {
		t.Fatalf("DeprecateAssets failed: %v", err)
	} else if len(be.objects) == 0 {
		t.Fatalf("a recent object was deleted: %v", err)
	}
}

func TestAssetStorageConfiguration(t *testing.T) {
	dashMock := newDashMock()
	cfg := &Config{
		UploadTo: "test://test",
		Assets: map[Type]TypeConfig{
			BootableDisk:       {Always: true},
			HTMLCoverageReport: {Never: true},
		},
	}
	storage, err := StorageFromConfig(cfg, dashMock.getDashapi())
	if err != nil {
		t.Fatalf("unexpected error from StorageFromConfig: %s", err)
	}
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}

	// Uploading a file of a disabled asset type.
	htmlContent := []byte("<html><head><title>Hi!</title></head></html>")
	err = storage.UploadBuildAsset(bytes.NewReader(htmlContent), "cover_report.html",
		HTMLCoverageReport, build)
	if !errors.Is(err, ErrAssetTypeDisabled) {
		t.Fatalf("UploadBuildAssetStream expected to fail with ErrAssetTypeDisabled, but got %v", err)
	}

	// Uploading a file of an enabled asset type.
	testContent := []byte{0x1, 0x2, 0x3, 0x4}
	err = storage.UploadBuildAsset(bytes.NewReader(testContent), "disk.raw", BootableDisk, build)
	if err != nil {
		t.Fatalf("UploadBuildAssetStream of BootableDisk expected to succeed, got %v", err)
	}

	// Uploading a file of an unspecified asset type.
	err = storage.UploadBuildAsset(bytes.NewReader(testContent), "disk.raw", KernelImage, build)
	if !errors.Is(err, ErrAssetTypeDisabled) {
		t.Fatalf("UploadBuildAssetStream expected to fail with ErrAssetTypeDisabled, but got %v", err)
	}
}
