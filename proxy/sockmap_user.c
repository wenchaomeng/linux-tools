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
#include "bpf_load.h"
#include "bpf_util.h"

#define MAXSIZE	1024
#define CGROUP  "/sys/fs/cgroup/bpf"
char buf[MAXSIZE];
static int proxysd1;

static int sockmap_fd, proxymap_fd, bpf_prog_fd;
static int progs_fd[3];
static int maps_fd[2];
struct bpf_map *maps[2];

static int key, val;
static int ctrl = 0;

static void int_handler(int a)
{
	close(proxysd1);
	exit(0);
}

// 可以通过发送HUP信号来打开和关闭sockmap offload功能
static void hup_handler(int a)
{
	key = 1;
	bpf_map_delete_elem(sockmap_fd, &key);
}

char *map_names[] = {
	"proxy_map",
	"sock_map"
};


int prog_attach_type[] = {
	BPF_SK_SKB_STREAM_PARSER,
	BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_SOCK_OPS
};

int prog_type[] = {
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_SOCK_OPS
};

static int populate_progs(char *bpf_file)
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	int i = 0;
	long err;

	printf("-------------\n");
	obj = bpf_object__open(bpf_file);
	printf("-------------\n");
	err = libbpf_get_error(obj);
	printf("-------------\n");
	if (err) {
		char err_buf[256];

		libbpf_strerror(err, err_buf, sizeof(err_buf));
		printf("Unable to load eBPF objects in file '%s' : %s\n",
		       bpf_file, err_buf);
		return -1;
	}

	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, prog_type[i]);
		bpf_program__set_expected_attach_type(prog,
						      prog_attach_type[i]);
		i++;
	}

	i = bpf_object__load(obj);
	i = 0;
	bpf_object__for_each_program(prog, obj) {
		progs_fd[i] = bpf_program__fd(prog);
		i++;
	}

	for (i = 0; i < sizeof(maps_fd)/sizeof(int); i++) {
		maps[i] = bpf_object__find_map_by_name(obj, map_names[i]);
		maps_fd[i] = bpf_map__fd(maps[i]);
		if (maps_fd[i] < 0) {
			fprintf(stderr, "load_bpf_file: (%i) %s\n",
				maps_fd[i], strerror(errno));
			return -1;
		}
	}

	return 0;
}

#define SOCKMAP_PARSE_PROG "./sockmap_parse_prog.o"
int parse_prog = 0;
void loadParseProg(){
	int err;
	struct bpf_object *obj;

	
	err = bpf_prog_load(SOCKMAP_PARSE_PROG,
			    BPF_PROG_TYPE_SK_SKB, &obj, &parse_prog);
	if (err) {
		printf("Failed to load SK_SKB parse prog\n");
	}
}

int connectToAuthServer(char *host, char* port){
	int sd;
	int err;
	struct sockaddr_in proxyaddr1;
	struct hostent *proxy1;
	unsigned short port1;

	proxy1 = gethostbyname(host);
	port1 = atoi(port);


	sd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&proxyaddr1, sizeof(struct sockaddr_in));
	proxyaddr1.sin_family = AF_INET;
	proxyaddr1.sin_port = htons(port1);
	proxyaddr1.sin_addr = *((struct in_addr *)proxy1->h_addr);

	err = connect(sd, (struct sockaddr *)&proxyaddr1, sizeof(struct sockaddr));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect c1 failed()");
		return errno;
	}
	return sd;
}
#define PATH_MAX        4096    /* # chars in a path name including nul */
static int join_cgroup_from_top(char *cgroup_path)
{
	char cgroup_procs_path[PATH_MAX + 1];
	pid_t pid = getpid();
	int fd, rc = 0;

	snprintf(cgroup_procs_path, sizeof(cgroup_procs_path),
		 "%s/cgroup.procs", cgroup_path);

	fd = open(cgroup_procs_path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "Opening Cgroup Procs: %s", cgroup_procs_path);
		return 1;
	}

	if (dprintf(fd, "%d\n", pid) < 0) {
		fprintf(stderr, "Joining Cgroup");
		rc = 1;
	}

	close(fd);
	return rc;
}
int prog_attach(int prog_fd, char *desc, int map_fd, enum bpf_attach_type attach_type){

	int err = 0;

    err = bpf_prog_attach(prog_fd, map_fd, attach_type, 0);
    if (err) {
                fprintf(stderr, "ERROR: bpf_prog_attach (groups) (%s) : prog_fd:%d, map(cgroup)_fd:%d, %d (%s)\n",
                        desc, progs_fd[2], map_fd, err, strerror(errno));
	}

    return err;
}

int prog_detach(int prog_fd, char *desc, int map_fd, enum bpf_attach_type attach_type){

	int err = 0;
    err = bpf_prog_detach2(prog_fd, map_fd, attach_type);
    if (err) {
                fprintf(stderr, "ERROR: bpf_prog_detach (groups) (%s) : prog_fd:%d, map(cgroup)_fd:%d, %d (%s)\n",
                        desc, progs_fd[2], map_fd, err, strerror(errno));
	}

    return err;

}

int main(int argc, char **argv)
{
	char filename[256];
	int ret;
	fd_set rset;
	int maxfd = 10;
	int cg_fd;
	int err;
	
	if (argc != 3) {
		printf("argc %d, expected: 3 \n", argc);
                exit(1);
        }

	//open cgroup
         cg_fd = open(CGROUP, O_DIRECTORY, O_RDONLY);
         if (cg_fd < 0) {
         	fprintf(stderr,
         	"ERROR: (%i) open cg path failed: %s\n",
         	cg_fd, optarg);
         	return cg_fd;
         }
	join_cgroup_from_top(CGROUP);	

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	populate_progs(filename);

//	loadParseProg();


	proxymap_fd = maps_fd[0];
	sockmap_fd = maps_fd[1];

	//attach prog
	prog_attach(progs_fd[0], "parse prog", sockmap_fd, BPF_SK_SKB_STREAM_PARSER);
	prog_attach(progs_fd[1], "verdict prog", sockmap_fd, BPF_SK_SKB_STREAM_VERDICT);
    prog_attach(progs_fd[2], "sock ops" , cg_fd, BPF_CGROUP_SOCK_OPS);

	proxysd1 = connectToAuthServer(argv[1], argv[2]);

	if( 1 ){
		int port1 = atoi(argv[2]);
		key = port1;
		val = 0;
		bpf_map_update_elem(proxymap_fd, &key, &val, BPF_ANY);
		key = 1;
		bpf_map_update_elem(sockmap_fd, &key, &proxysd1, BPF_ANY);
	}
	
	printf("press any key to continue!");
	getchar();

	prog_detach(progs_fd[2], "sock ops",  cg_fd, BPF_CGROUP_SOCK_OPS);
	prog_detach(progs_fd[1], "verdict",  sockmap_fd, BPF_SK_SKB_STREAM_VERDICT);
	prog_detach(progs_fd[0], "parse", sockmap_fd, BPF_SK_SKB_STREAM_PARSER);

	close(cg_fd);
	return 0;
}

