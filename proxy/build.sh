
KERNEL_HOME=/home/wenchao/kernel-src
clang -O2 -target bpf -c sockmap_kern.c -o sockmap_user_kern.o
#clang -O2 -target bpf -c sockmap_parse_prog.c -o sockmap_parse_prog.o
#clang -O2 -target bpf -c sockmap_parse_prog1.c -o sockmap_parse_prog.o
gcc sockmap_user.c $KERNEL_HOME/tools/testing/selftests/bpf/libbpf.a   -lelf   -o sockmap_user
