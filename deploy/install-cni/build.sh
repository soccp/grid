#!/bin/bash
# 编译grid
GO111MODULE=off CGO_ENABLED=0 go build -o bin/grid $GOPATH/src/github.com/projectcalico/cni-plugin
# 编译grid-ipam
GO111MODULE=off CGO_ENABLED=0 go build -o bin/grid-ipam $GOPATH/src/github.com/projectcalico/cni-plugin/ipam
# 生成Docker镜像
VERSION=`date "+%Y%m%d"`
docker build -t socp.io/library/install-cni:$VERSION
