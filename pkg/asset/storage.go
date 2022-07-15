// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

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

func (storage *Storage) UploadFile(origFile string, assetType Type, name string) (string, error) {
	storage.tracer.Log("UploadFile(%#v, %#v, %#v)", origFile, assetType, name)
	if name == "" {
		return "", fmt.Errorf("file name is not specified")
	}
	if !storage.AssetTypeEnabled(assetType) {
		return "", fmt.Errorf("didn't upload an asset of type %s: %w",
			assetType, ErrAssetTypeDisabled)
	}
	// The idea is to make a file name useful and yet unique.
	// So we put a file to a pseudo-unique "folder".
	path := fmt.Sprintf("%v/%s", time.Now().UnixNano(), name)
	req := &uploadRequest{
		origFile: origFile,
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

func (storage *Storage) UploadBuildAsset(origFile string, assetType Type, build *dashapi.Build) error {
	baseName := filepath.Base(origFile)
	fileExt := filepath.Ext(baseName)
	name := fmt.Sprintf("%s-%s%s",
		strings.TrimSuffix(baseName, fileExt),
		build.KernelCommit,
		fileExt)
	url, err := storage.UploadFile(origFile, assetType, name)
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

func (storage *Storage) UploadBuildAssetStream(reader io.Reader, assetType Type, fileName string,
	build *dashapi.Build) error {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpFile := filepath.Join(dir, fileName)
	w, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create a temp file: %w", err)
	}
	_, err = io.Copy(w, reader)
	if err != nil {
		return fmt.Errorf("failed to write the reader stream: %w", err)
	}
	w.Close()
	defer os.Remove(tmpFile)
	return storage.UploadBuildAsset(tmpFile, assetType, build)
}

func (storage *Storage) UploadBuildAssetCopy(origFile string, assetType Type, copyName string,
	build *dashapi.Build) error {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpFile := filepath.Join(dir, copyName)
	if err := osutil.CopyFile(origFile, tmpFile); err != nil {
		return fmt.Errorf("failed to copy the file: %w", err)
	}
	defer os.Remove(tmpFile)
	return storage.UploadBuildAsset(tmpFile, assetType, build)
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
	origFile        string
	savePath        string
	contentEncoding string
	contentType     string
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
	// Map cannot be concurrently accessed.
	mu sync.Mutex
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
	ap.mu.Lock()
	defer ap.mu.Unlock()
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

const xzTimeout = 5 * time.Minute
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
		// Prepare the temporary file.
		tmpFile, err := ioutil.TempFile("", "preproc-xz")
		if err != nil {
			return nil, fmt.Errorf("xz preprocess: failed to create a tmp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		cmd := osutil.Command("xz", fmt.Sprintf("-%d", xzCompressionRatio),
			"-T", fmt.Sprintf("%d", xzThreadsCount), "-F", "xz",
			"-c", req.origFile)
		cmd.Stdout = tmpFile
		_, err = osutil.Run(xzTimeout, cmd)
		if err != nil {
			return nil, fmt.Errorf("xz preprocess: command run failed: %w", err)
		}
		newReq := *req
		newReq.origFile = tmpFile.Name()
		newReq.savePath = fmt.Sprintf("%s.xz", newReq.savePath)
		return next(&newReq)
	},
}

const gzipCompressionRatio = 4

var PreprocessGzip = Preprocessor{
	Do: func(req *uploadRequest,
		next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error) {
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
		file, err := os.Create(tmpName)
		if err != nil {
			return nil, fmt.Errorf("gzip preprocess: failed to open the tmp file: %w", err)
		}
		defer file.Close()
		writer := bufio.NewWriter(file)
		// Compress the file.
		gzip, err := gzip.NewWriterLevel(writer, gzipCompressionRatio)
		if err != nil {
			return nil, fmt.Errorf("gzip preprocess: NewWriterLevel failed: %w", err)
		}
		io.Copy(gzip, origFile)
		gzip.Close()
		writer.Flush()
		// Pass control further.
		newReq := *req
		newReq.origFile = tmpName
		newReq.savePath = fmt.Sprintf("%s.gz", newReq.savePath)
		newReq.contentType = "application/gzip"
		return next(&newReq)
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
