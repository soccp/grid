容器配置网络过程


# 1 kubelet配置Pause容器
D:/mygo/src/github.com/kubernetes/kubernetes/pkg/kubelet/dockershim/docker_sandbox.go 163
```
	// Step 5: Setup networking for the sandbox.
	// All pod networking is setup by a CNI plugin discovered at startup time.
	// This plugin assigns the pod ip, sets up routes inside the sandbox,
	// creates interfaces etc.
```

D:/mygo/src/github.com/kubernetes/kubernetes/pkg/kubelet/network/plugins.go 413

```
pm.plugin.SetUpPod(podNamespace, podName, id, annotations)
```

D:/mygo/src/github.com/kubernetes/kubernetes/pkg/kubelet/network/cni/cni.go 225

```
_, err = plugin.addToNetwork(plugin.getDefaultNetwork(), name, namespace, id, netnsPath)
```

D:/mygo/src/github.com/kubernetes/kubernetes/pkg/kubelet/network/cni/cni.go 257 

```
res, err := cniNet.AddNetworkList(netConf, rt)

type NetConf struct {
	CNIVersion string `json:"cniVersion,omitempty"`

	Name         string          `json:"name,omitempty"`
	Type         string          `json:"type,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	IPAM         struct {
		Type string `json:"type,omitempty"`
	} `json:"ipam,omitempty"`
	DNS DNS `json:"dns"`
}

	rt := &libcni.RuntimeConf{
		ContainerID: podSandboxID.ID,
		NetNS:       podNetnsPath,
		IfName:      network.DefaultInterfaceName,
		Args: [][2]string{
			{"IgnoreUnknown", "1"},
			{"K8S_POD_NAMESPACE", podNs},
			{"K8S_POD_NAME", podName},
			{"K8S_POD_INFRA_CONTAINER_ID", podSandboxID.ID},
		},
	}
```

D:/mygo/src/github.com/kubernetes/kubernetes/vendor/github.com/containernetworking/cni/libcni/api.go

```
func (c *CNIConfig) AddNetworkList(list *NetworkConfigList, rt *RuntimeConf) (types.Result, error) {
	var prevResult types.Result
	for _, net := range list.Plugins {
		pluginPath, err := invoke.FindInPath(net.Network.Type, c.Path)
		if err != nil {
			return nil, err
		}

		newConf, err := buildOneConfig(list, net, prevResult, rt)
		if err != nil {
			return nil, err
		}

		prevResult, err = invoke.ExecPluginWithResult(pluginPath, newConf.Bytes, c.args("ADD", rt))
		if err != nil {
			return nil, err
		}
	}

	return prevResult, nil
}


func ExecPluginWithResult(pluginPath string, netconf []byte, args CNIArgs) (types.Result, error) {
	return defaultPluginExec.WithResult(pluginPath, netconf, args)
}
```

# 2 calico接收请求进行处理
## 2.1 概述
###   calico输入与输出
```
cmdAdd(args *skel.CmdArgs) error
```

```
type CmdArgs struct {
	ContainerID string
	Netns       string
	IfName      string
	Args        string 
	Path        string
	StdinData   []byte //calico配置文件
}
```
### calico配置文件示例
```
{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.0",
  "plugins": [
    {
      "type": "calico",
      "log_level": "debug",
      "etcd_endpoints": "http://10.96.232.136:6666",
      "etcd_key_file": "",
      "etcd_cert_file": "",
      "etcd_ca_cert_file": "",
      "mtu": 1440,
      "ipam": {
          "type": "calico-ipam"
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "/etc/cni/net.d/calico-kubeconfig"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    }
  ]
}
```
## 2.2流程
### 2.2.1 解析输入信息
### 2.2.2 根据输入容器信息生成workload信息
### 2.2.3 根据生成的workload信息请求etcd判断是否存在 若存在进行2.2.6.2操作 
### 2.2.4 判断容器类型
### 2.2.5 判断cni-plugin
### 2.2.6 请求calico-ipam 分配Ip
#### 2.2.6.1 判断是否有本机可用的Ip池
#### 2.2.6.2 获取本机Ip解析所在ip段信息，从etcd获取可用网段，并进行匹配。生成可用的ip池。并生成绑定关系。
```
root@zk-1:~# etcdcalico3 get /calico --prefix --keys-only |grep 13.
/calico/ipam/v2/assignment/ipv4/block/192.168.13.150-23
/calico/ipam/v2/host/192.168.12.0-23/ipv4/block/192.168.13.150-23
```
```
{
    "affinity": "host:172.16.30.0-24",
    "allocations": [
        0,
        null,
        null,
        null,
        null
    ],
    "attributes": [
        {
            "handle_id": "k8s-pod-network.c835e1c73bf36d0714d9bc7e98aabd364e5842455b3a4273d9c33ffdcb9c0c55",
            "secondary": null
        }
    ],
    "cidr": "172.16.30.250/24",
    "strictAffinity": false,
    "unallocated": [
        1,
        2,
        3,
        4
    ]
}

root@172:~/test# etcdcalico3 get /calico/ipam/v2/host/172.16.30.0-24/ipv4/block/172.16.30.250-24 --print-value-only
{"state":"confirmed"}
```
#### 2.2.6.3 从ip池内获取可用Ip 返回给calico
#### 2.2.6.4 calico在给定的网络空间内生成veth对，为容器端网卡生成mac,配置Ip,配置网关，添加路由信息。然后将host端网卡移到host网络空间内，配置网桥。
#### 2.2.6.5 完成网络配置 生成workload信息 存入etcd.







  
  






	
