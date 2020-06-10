#!/bin/bash
clang -O2 -target bpf -c classifier.c -o classifier.o
#clang -O2 -g -c -target bpf -c classifier.c -o classifier.o
