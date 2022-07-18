// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/syzkaller/pkg/gcs"
)

type CloudStorageBackend struct {
	client *gcs.Client
	bucket string
}

func MakeCloudStorageBackend(bucket string) (*CloudStorageBackend, error) {
	client, err := gcs.NewClient()
	if err != nil {
		return nil, fmt.Errorf("the call to NewClient failed: %w", err)
	}
	return &CloudStorageBackend{
		client: client,
		bucket: bucket,
	}, nil
}

func (csb *CloudStorageBackend) upload(req *uploadRequest) (*uploadResponse, error) {
	path := fmt.Sprintf("%s/%s", csb.bucket, req.savePath)
	w, err := csb.client.FileWriterExt(req.savePath, req.contentType, req.contentEncoding)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(w, req.reader); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	url, err := csb.client.GetDownloadURL(path)
	if err != nil {
		// The file would have been deleted later during clean up, but why not do it right away?
		csb.client.DeleteFile(path)
	}
	return &uploadResponse{downloadURL: url}, nil
}

func (csb *CloudStorageBackend) list() ([]storedObject, error) {
	list, err := csb.client.ListObjects(csb.bucket)
	if err != nil {
		return nil, err
	}
	ret := []storedObject{}
	for _, obj := range list {
		ret = append(ret, storedObject{
			downloadURL: obj.DownloadURL,
			createdAt:   obj.CreatedAt,
		})
	}
	return ret, nil
}

func (csb *CloudStorageBackend) remove(downloadURL string) error {
	// We need to fetch the file path from the URL.
	u, err := url.Parse(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to parse the URL: %w", err)
	}
	parts := strings.SplitN(u.Path, csb.bucket+"/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%s/ is not present in the path %s", csb.bucket, u.Path)
	}
	err = csb.client.DeleteFile(parts[1])
	if err == gcs.ErrFileNotFound {
		return ErrAssetDoesNotExist
	}
	return err
}
