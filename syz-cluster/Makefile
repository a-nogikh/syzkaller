# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

restart-spanner:
	minikube addons disable cloud-spanner;
	minikube addons enable cloud-spanner

build-controller-dev:
	docker build -t controller-image-local ./controller/src/

build-db-mgmt-dev:
	eval $$(minikube docker-env);\
	docker build -t db-mgmt-local -f Dockerfile.db-mgmt .

start-dev: minikube start; minikube-env;
	build-controller-dev
	build-db-mgmt-dev
	restart-spanner
	minikube kubectl -- kubectl apply -k ./overlays/dev/
