#!/bin/bash
kubectl create ns cni
kubectl -n cni create secret generic etcd-certs --from-file=/etc/kubernetes/pki/etcd/server.crt --from-file=/etc/kubernetes/pki/etcd/server.key --from-file=/etc/kubernetes/pki/etcd/ca.crt
