KERNEL_HOME=/home/wenchao/kernel-src
#clang -O2 -target bpf -c sockmap_kern.c -o sockmap_user_kern.o
gcc user.c $KERNEL_HOME/tools/testing/selftests/bpf/libbpf.a   -lelf   -o user
