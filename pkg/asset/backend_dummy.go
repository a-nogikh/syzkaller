// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"fmt"
	"time"
)

type objectUploadCallback func(req *uploadRequest) error
type objectRemoveCallback func(url string) error

type testObject struct {
	createdAt       time.Time
	contentType     string
	contentEncoding string
}

type testStorageBackend struct {
	currentTime  time.Time
	objects      map[string]*testObject
	objectUpload objectUploadCallback
	objectRemove objectRemoveCallback
}

func makeTestStorageBackend() *testStorageBackend {
	return &testStorageBackend{
		currentTime: time.Now(),
		objects:     make(map[string]*testObject),
	}
}

func (be *testStorageBackend) upload(req *uploadRequest) (*uploadResponse, error) {
	if be.objectUpload != nil {
		if err := be.objectUpload(req); err != nil {
			return nil, err
		}
	}
	url := "http://google.com/" + req.savePath
	be.objects[url] = &testObject{
		createdAt:       be.currentTime,
		contentType:     req.contentType,
		contentEncoding: req.contentEncoding,
	}
	return &uploadResponse{url}, nil
}

func (be *testStorageBackend) list() ([]storedObject, error) {
	ret := []storedObject{}
	for url, obj := range be.objects {
		ret = append(ret, storedObject{
			downloadURL: url,
			createdAt:   obj.createdAt,
		})
	}
	return ret, nil
}

func (be *testStorageBackend) remove(url string) error {
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

func (be *testStorageBackend) hasOnly(urls []string) error {
	notEqual := false
	if len(urls) != len(be.objects) {
		notEqual = true
	}
	for _, url := range urls {
		if _, ok := be.objects[url]; !ok {
			notEqual = true
			break
		}
	}
	if notEqual {
		return fmt.Errorf("object sets are not equal; needed %#v", urls)
	}
	return nil
}
