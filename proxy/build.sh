clang -O2 -target bpf -c sockmap_kern.c -o sockmap_user_kern.o
gcc sockmap_user.c /home/wenchao/kernel-src/tools/testing/selftests/bpf/libbpf.a   -lelf   -o sockmap_user
