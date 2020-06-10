#!/bin/bash
IFNAME=enp0s3
IFNAME=lo
sudo tc qdisc add dev $IFNAME handle 0: ingress
sudo tc filter add dev $IFNAME ingress  bpf direct-action obj classifier.o flowid 0:
