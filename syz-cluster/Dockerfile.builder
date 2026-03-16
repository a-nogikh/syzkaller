# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
FROM gcr.io/syzkaller/env AS builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

ARG GO_FLAGS

# Build syzkaller.
COPY --exclude=.git --exclude=syz-cluster . .
RUN make TARGETARCH=amd64

# Build syz-cluster tools.
COPY syz-cluster ./syz-cluster
RUN cd syz-cluster && CGO_ENABLED=0 make -j all

# Final stage to retain only built binaries, keeping the image small.
FROM scratch
COPY --from=builder /build/bin/ /build/bin/
COPY --from=builder /build/syz-cluster/bin/ /build/syz-cluster/bin/
