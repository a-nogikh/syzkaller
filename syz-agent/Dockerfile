# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM gcr.io/syzkaller/env AS syz-agent-builder
WORKDIR /syzkaller

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN make target OS=linux
RUN make agent

FROM gcr.io/syzkaller/syzbot
WORKDIR /app

COPY --from=syz-agent-builder /syzkaller/bin/syz-agent /app/syz-agent
COPY --from=syz-agent-builder /syzkaller/bin/ /syzkaller/bin/
COPY --from=syz-agent-builder /syzkaller/sys/ /syzkaller/sys/

ENTRYPOINT ["/app/syz-agent", "-syzkaller=/syzkaller"]
