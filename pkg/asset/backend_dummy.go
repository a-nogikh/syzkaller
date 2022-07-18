// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"fmt"
	"time"
)

type objectUploadCallback func(req *uploadRequest) (*uploadResponse, error)
type objectRemoveCallback func(url string) error

type dummyObject struct {
	createdAt       time.Time
	contentType     string
	contentEncoding string
}

type dummyStorageBackend struct {
	currentTime  time.Time
	objects      map[string]*dummyObject
	objectUpload objectUploadCallback
	objectRemove objectRemoveCallback
}

func makeDummyStorageBackend() *dummyStorageBackend {
	return &dummyStorageBackend{
		currentTime: time.Now(),
		objects:     make(map[string]*dummyObject),
	}
}

type dummyWriteCloser struct {
}

func (dwc *dummyWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (dwc *dummyWriteCloser) Close() error {
	return nil
}

func (be *dummyStorageBackend) upload(req *uploadRequest) (*uploadResponse, error) {
	url := "http://download/" + req.savePath
	be.objects[url] = &dummyObject{
		createdAt:       be.currentTime,
		contentType:     req.contentType,
		contentEncoding: req.contentEncoding,
	}
	if be.objectUpload != nil {
		return be.objectUpload(req)
	}
	return &uploadResponse{writer: &dummyWriteCloser{}}, nil
}

func (be *dummyStorageBackend) downloadURL(path string, publicURL bool) (string, error) {
	return "http://download/" + path, nil
}

func (be *dummyStorageBackend) list() ([]storedObject, error) {
	ret := []storedObject{}
	for url, obj := range be.objects {
		ret = append(ret, storedObject{
			downloadURL: url,
			createdAt:   obj.createdAt,
		})
	}
	return ret, nil
}

func (be *dummyStorageBackend) remove(url string) error {
	if be.objectRemove != nil {
		if err := be.objectRemove(url); err != nil {
			return err
		}
	}
	if _, ok := be.objects[url]; !ok {
		return ErrAssetDoesNotExist
	}
	delete(be.objects, url)
	return nil
}

func (be *dummyStorageBackend) hasOnly(urls []string) error {
	makeError := func() error {
		return fmt.Errorf("object sets are not equal; needed: %#v; uploaded: %#v", urls, be.objects)
	}
	if len(urls) != len(be.objects) {
		return makeError()
	}
	for _, url := range urls {
		if be.objects[url] == nil {
			return makeError()
		}
	}
	return nil
}
