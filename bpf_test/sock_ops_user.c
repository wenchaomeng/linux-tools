// sockmap_user.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <arpa/inet.h>
#include "include/bpf_load.h"
#include "include/bpf_util.h"

#define CGROUP  "/sys/fs/cgroup/bpf"


int prog_attach(int prog_fd, char *desc, int map_fd, enum bpf_attach_type attach_type){

	int err = 0;

    err = bpf_prog_attach(prog_fd, map_fd, attach_type, 0);
    if (err) {
                fprintf(stderr, "ERROR: bpf_prog_attach (groups) (%s) : prog_fd:%d, map(cgroup)_fd:%d, %d (%s)\n",
                        desc, prog_fd, map_fd, err, strerror(errno));
	}

    return err;
}

int prog_detach(int prog_fd, char *desc, int map_fd, enum bpf_attach_type attach_type){

	int err = 0;
    err = bpf_prog_detach2(prog_fd, map_fd, attach_type);
    if (err) {
                fprintf(stderr, "ERROR: bpf_prog_detach (groups) (%s) : prog_fd:%d, map(cgroup)_fd:%d, %d (%s)\n",
                        desc, prog_fd, map_fd, err, strerror(errno));
	}

    return err;

}

int main(int argc, char **argv)
{
	char filename[256];
	int cg_fd;
	int err;
	int prog;
	struct bpf_object *obj;

	
	//open cgroup
    cg_fd = open(CGROUP, O_DIRECTORY, O_RDONLY);
     if (cg_fd < 0) {
         	fprintf(stderr, "ERROR: (%i) open cg path failed: %s\n", cg_fd, optarg);
         	return cg_fd;
    }

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	fprintf(stdout, "begin bpf load:%s \n", filename);
	err = bpf_prog_load(filename, BPF_PROG_TYPE_SOCK_OPS, &obj, &prog);
	if (err) {
    	fprintf(stderr, "ERROR: bpf_prog_load error %d(%s)\n",  err, strerror(errno));
		return err;
    }



	//attach prog
    prog_attach(prog, "sock ops" , cg_fd, BPF_CGROUP_SOCK_OPS);
	
	getchar();

	prog_detach(prog, "sock ops",  cg_fd, BPF_CGROUP_SOCK_OPS);

	close(cg_fd);
	return 0;
}
