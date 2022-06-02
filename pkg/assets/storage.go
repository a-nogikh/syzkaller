// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assets

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/osutil"
)

type AssetStorage struct {
	name     string
	cfg      *Config
	backend  AssetStorageBackend
	handlers AssetPreprocessors
	dash     *dashapi.Dashboard
}

// TODO: logging

func AssetStorageFromConfig(name string, cfg *Config, dash *dashapi.Dashboard) *AssetStorage {
	return &AssetStorage{
		name:    name,
		cfg:     cfg,
		backend: MakeCloudStorageBackend(c.GcsBucket),
		handers: DefaultAssetPreprocessors(),
		dash:    dash,
	}
}

func (storage *AssetStorage) AssetTypeEnabled(assetType string) bool {
	return storage.cfg.IsEnabled(assetType)
}

func (storage *AssetStorage) UploadFile(origFile, assetType, name string) (
	string, error) {
	if name == "" {
		name = assetType
	}
	// The idea is to make a file name useful and yet unique.
	// So we put a file to a pseudo-unique "folder".
	path := fmt.Sprintf("%v/%s", time.Now().UnixNano(), name)
	req := &uploadRequest{
		origFile: origFile,
	}
	res, err := storage.handlers.GetPreprocessor(assetType)(func(req *uploadRequest) {
		return storage.be.upload(req)
	})
	if err != nil {
		return "", err
	}
	return res.DownloadURL, nil
}

type BuildInfo struct {
	BuildID     string
	BuildCommit string
}

func (storage *AssetStorage) UploadBuildAsset(origFile, assetType string, build *BuildInfo) error {
	baseName := filepath.Base(origFile)
	fileExt := filepath.Ext(baseName)
	name := fmt.Sprintf("%s-%s%s",
		strings.TrimSuffix(baseName, fileExt),
		build.BuildCommit,
		fileExt)
	url, err := storage.UploadFile(origFile, name, assetType)
	if err != nil {
		return err
	}
	err = storage.dash.AddBuildAsset(&AddBuildAssetReq{
		BuildID:      build.BuildID,
		AssetStorage: storage.name,
		AssetType:    assetType,
		DownloadURL:  url,
	})
	if err != nil {
		// Dashboard did not accept this asset from us, so now we need
		// to remove it - it won't go through the normal asset deprecation
		// process anyway.
		storage.RemoveAsset(url)
		// TODO: if the RemoveAsset method fails, we actually have + 1 leaked
		// file. Such files will pile up and eat disk space.
		// For now let's just hope that these cases would be very very rare.
	}
	return err
}

func (storage *AssetStorage) UploadBuildAssetStream(reader io.Reader, assetType, fileName string,
	build *BuildInfo) (url string, err error) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpFile := filepath.Join(dir, fileName)
	w, err := os.Create(tmpFile)
	if err != nil {
		return "", fmt.Errorf("failed to create a temp file: %w", err)
	}
	_, err = io.Copy(w, reader)
	if err != nil {
		return "", fmt.Errorf("failed to write the reader stream: %w", err)
	}
	w.Close()
	defer os.Remove(tmpFile)
	return storage.UploadBuildAsset(tmpFile, assetType, build)
}

func (storage *AssetStorage) UploadBuildAssetCopy(origFile, assetType, copyName string,
	build *BuildInfo) (string, error) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpFile := filepath.Join(dir, fileName)
	defer os.Remove(tmpFile)
	err := osutil.CopyFile(origFile, tmpFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy the file: %w", err)
	}
	return storage.UploadBuildAsset(tmpFile, assetType, build)
}

var AssetDidNotExist = errors.New("the asset did not exist")

func (storage *AssetStorage) RemoveAsset(downloadURL string) error {
	return storage.be.remove(downloadURL)
}

func (storage *AssetStorage) DeprecateAssets() error {
	resp, err := storage.dash.DeprecatedAssetsList(&dashapi.DeprecatedAssetsList{
		AssetStorage: storage.name,
	})
	if err != nil {
		return err
	}
	deleted := []string{}
	for _, url := range resp.DeprecatedDownloadURLs {
		err := storage.DeleteAsset(url)
		if err == nil || err == AssetDidNotExist {
			deleted = append(deleted, url)
		} else {
			// TODO: print error?
		}
	}
	return storage.dash.ForgetAssets(&ForgetAssetsReq{DownloadURLs: deleted})
}

type uploadRequest struct {
	origFile        string
	savePath        string
	contentEncoding string
	contentType     string
}

type uploadReponse struct {
	downloadURL string
}

type AssetStorageBackend interface {
	upload(req *uploadRequest) (*uploadReponse, error)
	remove(url string) error
}

type CloudStorageBackend struct {
	client gcs.Client
	bucket string
}

func MakeCloudStorageBackend(bucket string) *CloudStorageBackend {
	return &CloudStorageBackend{
		client: gcs.NewClient(),
		bucket: bucket,
	}
}

func (csb *CloudStorageBackend) upload(req *uploadRequest) (*uploadReponse, error) {
	path := fmt.Sprintf("%s/%s", csb.bucket, req.savePath)
	err := csb.client.UploadFile(req.origFile, req.savePath)
	if err != nil {
		return nil, err
	}
	if req.contentType != "" || req.contentEncoding != "" {
		err = csb.client.SetContentMetadata(path, req.contentType, req.contentEncoding)
		if err != nil {
			// Unfortunately there's no easy way to guarantee that we won't leak anything.
			// So just try to delete the file -- we won't need it.
			csb.client.DeleteFile(path)
			return nil, err
		}
	}
	url, err := csb.client.GetDownloadURL(path)
	if err != nil {
		// Same reasoning as above.
		csb.client.DeleteFile(path)
	}
	return &uploadResponse{downloadURL: url}, nil
}

func (csb *CloudStorageBackend) remove(url string) error {
	// We need to fetch the file path from the URL.
	u, err := url.Parse(url)
	if err != nil {
		return fmt.Errorf("failed to parse the URL: %w", err)
	}
	pathStart := strings.Index(u.Path, csb.bucket+"/")
	if pathStart < 0 {
		return fmt.Errorf("bucket name is not present in the path %s", u.Path)
	}
	// TODO: figure out what would be the error when the file was not present.
	return csb.client.DeleteFile(u.Path[pathStart:])
}

type PreprocessorCollection struct {
	defaultOne Preprocessor
	custom     map[string]Preprocessor
	// Map cannot be concurrently accessed.
	mu sync.Mutex
}

func MakePreprocessorCollection(defaultOne Preprocessor,
	custom map[string]Preprocessor) *PreprocessorCollection {
	ret := &AssetPreprocessors{
		defaultOne: PreprocessGzip,
		custom:     custom,
	}
	for t, p := range custom {
		if !p.Available || p.Available() {
			ret.custom[t] = p
		}
	}
	return ret
}

func (ap *AssetPreprocessors) GetPreprocessor(assetType string) Preprocessor {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	p, ok := ap.custom[assetType]
	if ok {
		return p
	}
	return ap.defaultOne
}

type Preprocessor struct {
	Available  func() bool
	Preprocess func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadReponse, error)) (*uploadReponse, error)
}

var xzPresent bool
var xzCheck sync.Once

const xzTimeout = 5 * time.Minute
const xzCompressionRatio = 0
const xzThreadsCount = 6

var PreprocessXz = AssetPreprocessor{
	Available: func() bool {
		xzCheck.Do(func() {
			_, err := osutils.RunCmd(time.Minute, "", "xz --version")
			xzPresent = err != nil
		})
		return xzPresent
	},
	Preprocess: func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadReponse, error)) (*uploadReponse, error) {
		// Prepare the temporary file.
		tmpName, err := osutil.TempFile("preproc-xz")
		if err != nil {
			return nil, fmt.Errorf("xz preprocess: failed to create a tmp file: %w", err)
		}
		defer os.Remove(tmpName)
		cmd := fmt.Sprintf("xz -%d -T %d -F xz -c %s > %s", xzCompressionRatio,
			xzThreadsCount, req.origFile, tmpName)
		_, err := osutils.RunCmd(xzTimeout, "", cmd)
		if err != nil {
			return nil, fmt.Errorf("xz preprocess: command run failed: %w", err)
		}
		newReq := *req
		newReq.origFile = tmpName
		newReq.saveFile = fmt.Sprintf("%s.xz", newReq.saveFile)
		return next(&newReq)
	},
}

const gzipCompressionRatio = 4

var PreprocessGzip = AssetPreprocessor{
	Preprocess: func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadReponse, error)) (*uploadReponse, error) {
		// Open the original file.
		origFile, err := os.Open(req.origFile)
		if err != nil {
			return nil, fmt.Errorf("gzip preprocess: failed to open source file: %w", err)
		}
		defer origFile.Close()
		// Prepare the temporary file.
		tmpName, err := osutil.TempFile("preproc-gzip")
		if err != nil {
			return nil, fmt.Errorf("gzip preprocess: failed to create a tmp file: %w", err)
		}
		defer os.Remove(tmpName)
		file, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE, osutil.DefaultFilePerm)
		if err != nil {
			return nil, fmt.Errorf("gzip preprocess: failed to open the tmp file: %w", err)
		}
		defer file.Close()
		writer := bufio.NewWriter(file)
		defer writer.Close()
		// Compress the file.
		gzip := gzip.NewWriterLevel(witer, gzipCompressionRatio)
		io.Copy(gzip, origFile)
		// Pass control further.
		newReq := *req
		newReq.origFile = tmpName
		newReq.saveFile = fmt.Sprintf("%s.gz", newReq.saveFile)
		newReq.contentType = "application/gzip"
		return next(&newReq)
	},
}

var PreprocessHtml = AssetPreprocessor{
	Preprocess: func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadReponse, error)) (*uploadReponse, error) {
		PreprocessGzip.Preprocess(uploadRequest, func(req *uploadRequest) (*uploadReponse, error) {
			newReq := *req
			// We don't need the .gz suffix.
			newReq.saveFile = strings.TrimSuffix(newReq.saveFile, ".gz")
			// See https://cloud.google.com/storage/docs/transcoding#good_practices
			newReq.contentEncoding = "gzip"
			newReq.contentType = "text/html"
			next(&newReq)
		})
	},
}

// TODO: set it in the config files.
func DefaultAssetPreprocessors() *AssetPreprocessors {
	return MakePreprocessorCollection(PreprocessGzip, map[string]AssetPreprocessor{
		HtmlCoverageReport: PreprocessHtml,
		VmLinux:            PreprocessXz,
		KernelObject:       PreprocessXz,
		BootableDisk:       PreprocessXz,
	})
}
