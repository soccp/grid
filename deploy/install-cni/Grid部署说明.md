# Grid部署说明

## 准备条件 

物理机配置br0网桥 搭建k8s环境 解压grid.tar.gz 

## etcd配置

### 创建命令别名 便于后期查询etcd数据

```
alias etcd3='ETCDCTL_API=3 etcdctl --key="/etc/kubernetes/pki/etcd/server.key" --cacert="/etc/kubernetes/pki/etcd/ca.crt/kubernetes/pki/etcd/server.crt" --endpoints=https://192.168.14.41:2379'   ## 登录主节点将这行配置写入 /root/.bashrc 并source /root/.bashrc证书路径及etcd节点信息根据实际情况填写
```

### 部署grid cni组件

- 解压 install.tar.gz 

- 导入docker load -i cni.tar && docker push socp.io/library/install-cni:0903

- 执行setpool 脚本 具体执行方法执行 ./setpool help查看

- 创建etcd secret 

  ```
  bash create.sh 根据实际情况填写路径 一般用kubeadm 起的路径应该都一样
  ```

- kubectl apply -f grid.yaml ## 修改grid.yaml 中etcd_endpoints

