#!/bin/bash
IFNAME=enp0s3
IFNAME=lo
sudo tc qdisc del dev $IFNAME ingress
