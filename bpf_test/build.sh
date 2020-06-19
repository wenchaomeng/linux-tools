
KERNEL_HOME=/home/wenchao/kernel-src
clang -O2 -target bpf -c sock_ops_user_kern.c -o bin/sock_ops_user_kern.o
#clang -O2 -target bpf -c sockmap_parse_prog.c -o sockmap_parse_prog.o
#clang -O2 -target bpf -c sockmap_parse_prog1.c -o sockmap_parse_prog.o
gcc sock_ops_user.c $KERNEL_HOME/tools/testing/selftests/bpf/libbpf.a   -lelf   -o bin/sock_ops_user
