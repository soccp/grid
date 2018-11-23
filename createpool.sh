#!/bin/bash

alias etcdcalico3='ETCDCTL_API=3 etcdctl --endpoints="http://10.96.232.136:6666"'

etcdcalico3 put /calico/resources/v3/projectcalico.org/ippools/test '{"kind":"IPPool","apiVersion":"projectcalico.org/v3","metadata":{"name":"172.16.30_100-200","uid":"f571f014-e62c-11e8-afc6-000c2973c256","creationTimestamp":"2018-11-12T03:42:20Z"},"spec":{"cidr":"172.16.30.131/26","ipipMode":"Never","natOutgoing":true}}'
