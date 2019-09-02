FROM amd64/alpine:3.8

LABEL maintainer "ZhangKun <zhangkun1995@iie.ac.cn>"

ADD bin/amd64/ /opt/cni/bin/
ADD install-cni.sh /install-cni.sh
ADD grid.conf.tmp /grid.conf.tmp

ENV PATH=$PATH:/opt/cni/bin
VOLUME /opt/cni
WORKDIR /opt/cni/bin

