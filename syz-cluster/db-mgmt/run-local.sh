#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

alias kubectl="minikube kubectl --"
# Clean up in case the run comand was prematurely aborted.
kubectl delete pod db-mgmt >/dev/null 2>&1 || true
kubectl run db-mgmt --image=db-mgmt-local \
  --image-pull-policy=Never \
  --restart=Never \
  --env="SPANNER_EMULATOR_HOST=cloud-spanner-emulator:9010" \
  --rm \
  --attach \
  --command -- db-mgmt "$@"
