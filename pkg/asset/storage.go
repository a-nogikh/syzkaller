// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
)

type Storage struct {
	cfg           *Config
	backend       StorageBackend
	preprocessors *PreprocessorCollection
	dash          *dashapi.Dashboard
	tracer        debugtracer.DebugTracer
}

func StorageFromConfig(cfg *Config, dash *dashapi.Dashboard) (*Storage, error) {
	if dash == nil {
		return nil, fmt.Errorf("dashboard api instance is necessary")
	}
	tracer := debugtracer.DebugTracer(&debugtracer.NullTracer{})
	if cfg.Debug {
		tracer = &debugtracer.GenericTracer{
			WithTime:    true,
			TraceWriter: os.Stdout,
		}
	}
	var backend StorageBackend
	if strings.HasPrefix(cfg.UploadTo, "gs://") {
		var err error
		backend, err = MakeCloudStorageBackend(strings.TrimPrefix(cfg.UploadTo, "gs://"))
		if err != nil {
			return nil, fmt.Errorf("the call to MakeCloudStorageBackend failed: %w", err)
		}
	} else if strings.HasPrefix(cfg.UploadTo, "test://") {
		backend = makeTestStorageBackend()
	} else {
		return nil, fmt.Errorf("unknown UploadTo during StorageFromConfig(): %#v", cfg.UploadTo)
	}
	return &Storage{
		cfg:           cfg,
		backend:       backend,
		preprocessors: DefaultPreprocessors(),
		dash:          dash,
		tracer:        tracer,
	}, nil
}

func (storage *Storage) AssetTypeEnabled(assetType Type) bool {
	return storage.cfg.IsEnabled(assetType)
}

var ErrAssetTypeDisabled = errors.New("uploading assets of this type is disabled")

func (storage *Storage) UploadFileStream(reader io.Reader, assetType Type, name string) (string, error) {
	storage.tracer.Log("UploadStream(%#v, %#v)", assetType, name)
	if name == "" {
		return "", fmt.Errorf("file name is not specified")
	}
	if !storage.AssetTypeEnabled(assetType) {
		return "", fmt.Errorf("not allowed to upload an asset of type %s: %w",
			assetType, ErrAssetTypeDisabled)
	}
	// The idea is to make a file name useful and yet unique.
	// So we put a file to a pseudo-unique "folder".
	path := fmt.Sprintf("%v/%s", time.Now().UnixNano(), name)
	req := &uploadRequest{
		reader:   reader,
		savePath: path,
	}
	handler := storage.preprocessors.GetPreprocessor(assetType)
	res, err := handler.Do(req, func(req *uploadRequest) (*uploadResponse, error) {
		return storage.backend.upload(req)
	})
	if err != nil {
		return "", err
	}
	return res.downloadURL, nil
}

func (storage *Storage) UploadBuildAsset(reader io.Reader, fileName string, assetType Type, build *dashapi.Build) error {
	baseName := filepath.Base(fileName)
	fileExt := filepath.Ext(baseName)
	name := fmt.Sprintf("%s-%s%s",
		strings.TrimSuffix(baseName, fileExt),
		build.KernelCommit,
		fileExt)
	url, err := storage.UploadFileStream(reader, assetType, name)
	if err != nil {
		return err
	}
	// If the server denies the reques, we'll delete the orphaned file during deprecated files
	// deletion later.
	return storage.dash.AddBuildAsset(&dashapi.AddBuildAssetReq{
		BuildID:     build.ID,
		AssetType:   string(assetType),
		DownloadURL: url,
	})
}

var ErrAssetDoesNotExist = errors.New("the asset did not exist")

const deletionEmbargo = time.Hour * 24 * 7

func (storage *Storage) DeprecateAssets() error {
	resp, err := storage.dash.NeededAssetsList()
	if err != nil {
		return fmt.Errorf("failed to query needed assets: %w", err)
	}
	needed := map[string]bool{}
	for _, url := range resp.DownloadURLs {
		needed[url] = true
	}
	storage.tracer.Log("queried needed assets URLs: %#v", needed)
	existing, err := storage.backend.list()
	if err != nil {
		return fmt.Errorf("failed to query object list: %w", err)
	}
	toDelete := []string{}
	intersection := 0
	for _, obj := range existing {
		keep := false
		if time.Since(obj.createdAt) < deletionEmbargo {
			// To avoid races between object upload and object deletion, we don't delete
			// newly uploaded files for a while after they're uploaded.
			keep = true
		}
		if val, ok := needed[obj.downloadURL]; ok && val {
			keep = true
			intersection++
		}
		storage.tracer.Log("-- object %v, %v: keep %t", obj.downloadURL, obj.createdAt, keep)
		if !keep {
			toDelete = append(toDelete, obj.downloadURL)
		}
	}
	const intersectionCheckCutOff = 4
	if len(existing) > intersectionCheckCutOff && intersection == 0 {
		// This is a last-resort protection against possible dashboard bugs.
		// If the needed assets have no intersection with the existing assets,
		// don't delete anything. Otherwise, if it was a bug, we will lose all files.
		return fmt.Errorf("needed assets have some intersection with the existing ones")
	}
	for _, url := range toDelete {
		err := storage.backend.remove(url)
		storage.tracer.Log("-- deleted %v: %v", url, err)
		// Several syz-ci's might be sharing the same storage. So let's tolerate
		// races during file deletion.
		if err != nil && err != ErrAssetDoesNotExist {
			return fmt.Errorf("asset deletion failure: %w", err)
		}
	}
	return nil
}

type uploadRequest struct {
	savePath        string
	contentEncoding string
	contentType     string
	reader          io.Reader
}

type uploadResponse struct {
	downloadURL string
}

type storedObject struct {
	downloadURL string
	createdAt   time.Time
}

type StorageBackend interface {
	upload(req *uploadRequest) (*uploadResponse, error)
	list() ([]storedObject, error)
	remove(path string) error
}

type PreprocessorCollection struct {
	defaultOne Preprocessor
	custom     map[Type]Preprocessor
}

func MakePreprocessorCollection(defaultOne Preprocessor,
	custom map[Type]Preprocessor) *PreprocessorCollection {
	ret := &PreprocessorCollection{
		defaultOne: PreprocessGzip,
		custom:     custom,
	}
	for t, p := range custom {
		if p.Available == nil || p.Available() {
			ret.custom[t] = p
		}
	}
	return ret
}

func (ap *PreprocessorCollection) GetPreprocessor(assetType Type) Preprocessor {
	p, ok := ap.custom[assetType]
	if ok {
		return p
	}
	return ap.defaultOne
}

type Preprocessor struct {
	Available func() bool
	Do        func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error)
}

var xzPresent bool
var xzCheck sync.Once

const xzCompressionRatio = 0
const xzThreadsCount = 6

var PreprocessXz = Preprocessor{
	Available: func() bool {
		xzCheck.Do(func() {
			_, err := osutil.RunCmd(time.Minute, "", "xz --version")
			xzPresent = err != nil
		})
		return xzPresent
	},
	Do: func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error) {
		cmd := osutil.Command("xz", fmt.Sprintf("-%d", xzCompressionRatio),
			"-T", fmt.Sprintf("%d", xzThreadsCount), "-F", "xz", "-c")
		cmd.Stdin = req.reader
		var err error
		newReq := *req
		newReq.reader, err = cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
		}
		newReq.savePath = fmt.Sprintf("%s.xz", newReq.savePath)
		newReq.contentType = "application/x-xz"
		err = cmd.Start()
		if err != nil {
			return nil, fmt.Errorf("xz preprocess: command start failed: %w", err)
		}
		resp, err := next(&newReq)
		waitErr := cmd.Wait()
		if err == nil {
			err = waitErr
		}
		return resp, err
	},
}

const gzipCompressionRatio = 4

var PreprocessGzip = Preprocessor{
	Do: func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error) {
		pipeRead, pipeWrite, err := osutil.LongPipe()
		if err != nil {
			return nil, err
		}
		defer pipeRead.Close()
		// Compress the file.
		gzip, err := gzip.NewWriterLevel(pipeWrite, gzipCompressionRatio)
		if err != nil {
			return nil, fmt.Errorf("gzip preprocess: NewWriterLevel failed: %w", err)
		}
		retChan := make(chan []error)
		go func() {
			_, err := io.Copy(gzip, req.reader)
			errors := append([]error{}, err)
			errors = append(errors, gzip.Close())
			errors = append(errors, pipeWrite.Close())
			retChan <- errors
		}()
		// Pass control further.
		newReq := *req
		newReq.reader = pipeRead
		newReq.savePath = fmt.Sprintf("%s.gz", newReq.savePath)
		newReq.contentType = "application/gzip"
		resp, err := next(&newReq)
		for _, err := range <-retChan {
			if err != nil {
				return nil, err
			}
		}
		return resp, err
	},
}

var PreprocessHTML = Preprocessor{
	Do: func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error) {
		return PreprocessGzip.Do(req, func(req *uploadRequest) (*uploadResponse, error) {
			newReq := *req
			// We don't need the .gz suffix.
			newReq.savePath = strings.TrimSuffix(newReq.savePath, ".gz")
			// See https://cloud.google.com/storage/docs/transcoding#good_practices
			newReq.contentEncoding = "gzip"
			newReq.contentType = "text/html"
			return next(&newReq)
		})
	},
}

// TODO: set it in the config files.
func DefaultPreprocessors() *PreprocessorCollection {
	return MakePreprocessorCollection(PreprocessGzip, map[Type]Preprocessor{
		HTMLCoverageReport: PreprocessHTML,
		KernelImage:        PreprocessXz,
		KernelObject:       PreprocessXz,
		BootableDisk:       PreprocessXz,
		NonBootableDisk:    PreprocessXz,
	})
}
