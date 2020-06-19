
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Testsuite for eBPF maps
 *
 * Copyright (c) 2014 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2016 Facebook
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_util.h"
#include "bpf_rlimit.h"
#include "test_maps.h"

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <err.h>

#define MAX_ERRNO	4095

typedef __u8  u8;

static int skips;

static int map_flags;


#define SOCKMAP_PARSE_PROG "./sockmap_parse_prog.o"
#define SOCKMAP_VERDICT_PROG "./sockmap_verdict_prog.o"
#define SOCKMAP_TCP_MSG_PROG "./sockmap_tcp_msg_prog.o"
static void test_sockmap(unsigned int tasks, void *data)
{
	struct bpf_map *bpf_map_rx, *bpf_map_tx, *bpf_map_msg, *bpf_map_break;
	int map_fd_msg = 0, map_fd_rx = 0, map_fd_tx = 0, map_fd_break;
	int ports[] = {50200, 50201, 50202, 50204};
	int err, i, fd, udp, sfd[6] = {0xdeadbeef};
	u8 buf[20] = {0x0, 0x5, 0x3, 0x2, 0x1, 0x0};
	int parse_prog, verdict_prog, msg_prog;
	struct sockaddr_in addr;
	int one = 1, s, sc, rc;
	struct bpf_object *obj;
	struct timeval to;
	__u32 key, value;
	pid_t pid[tasks];
	fd_set w;

	/* Create some sockets to use with sockmap */
	for (i = 0; i < 2; i++) {
		sfd[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (sfd[i] < 0)
			goto out;
		err = setsockopt(sfd[i], SOL_SOCKET, SO_REUSEADDR,
				 (char *)&one, sizeof(one));
		if (err) {
			printf("failed to setsockopt\n");
			goto out;
		}
		err = ioctl(sfd[i], FIONBIO, (char *)&one);
		if (err < 0) {
			printf("failed to ioctl\n");
			goto out;
		}
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(ports[i]);
		err = bind(sfd[i], (struct sockaddr *)&addr, sizeof(addr));
		if (err < 0) {
			printf("failed to bind: err %i: %i:%i\n",
			       err, i, sfd[i]);
			goto out;
		}
		err = listen(sfd[i], 32);
		if (err < 0) {
			printf("failed to listen\n");
			goto out;
		}
	}

	for (i = 2; i < 4; i++) {
		sfd[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (sfd[i] < 0)
			goto out;
		err = setsockopt(sfd[i], SOL_SOCKET, SO_REUSEADDR,
				 (char *)&one, sizeof(one));
		if (err) {
			printf("set sock opt\n");
			goto out;
		}
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(ports[i - 2]);
		err = connect(sfd[i], (struct sockaddr *)&addr, sizeof(addr));
		if (err) {
			printf("failed to connect\n");
			goto out;
		}
	}


	for (i = 4; i < 6; i++) {
		sfd[i] = accept(sfd[i - 4], NULL, NULL);
		if (sfd[i] < 0) {
			printf("accept failed\n");
			goto out;
		}
	}

	/* Test sockmap with connected sockets */
	fd = bpf_create_map(BPF_MAP_TYPE_SOCKMAP,
			    sizeof(key), sizeof(value),
			    6, 0);
	if (fd < 0) {
		if (!bpf_probe_map_type(BPF_MAP_TYPE_SOCKMAP, 0)) {
			printf("%s SKIP (unsupported map type BPF_MAP_TYPE_SOCKMAP)\n",
			       __func__);
			skips++;
			for (i = 0; i < 6; i++)
				close(sfd[i]);
			return;
		}

		printf("Failed to create sockmap %i\n", fd);
		goto out_sockmap;
	}

	/* Test update with unsupported UDP socket */
	udp = socket(AF_INET, SOCK_DGRAM, 0);
	i = 0;
	err = bpf_map_update_elem(fd, &i, &udp, BPF_ANY);
	if (!err) {
		printf("Failed socket SOCK_DGRAM allowed '%i:%i'\n",
		       i, udp);
		goto out_sockmap;
	}

	/* Test update without programs */
	for (i = 0; i < 6; i++) {
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_ANY);
		if (i < 2 && !err) {
			printf("Allowed update sockmap '%i:%i' not in ESTABLISHED\n",
			       i, sfd[i]);
			goto out_sockmap;
		} else if (i >= 2 && err) {
			printf("Failed noprog update sockmap '%i:%i'\n",
			       i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Test attaching/detaching bad fds */
	err = bpf_prog_attach(-1, fd, BPF_SK_SKB_STREAM_PARSER, 0);
	if (!err) {
		printf("Failed invalid parser prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(-1, fd, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (!err) {
		printf("Failed invalid verdict prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(-1, fd, BPF_SK_MSG_VERDICT, 0);
	if (!err) {
		printf("Failed invalid msg verdict prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(-1, fd, __MAX_BPF_ATTACH_TYPE, 0);
	if (!err) {
		printf("Failed unknown prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, BPF_SK_SKB_STREAM_PARSER);
	if (err) {
		printf("Failed empty parser prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, BPF_SK_SKB_STREAM_VERDICT);
	if (err) {
		printf("Failed empty verdict prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, BPF_SK_MSG_VERDICT);
	if (err) {
		printf("Failed empty msg verdict prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, __MAX_BPF_ATTACH_TYPE);
	if (!err) {
		printf("Detach invalid prog successful\n");
		goto out_sockmap;
	}

	/* Load SK_SKB program and Attach */
	err = bpf_prog_load(SOCKMAP_PARSE_PROG,
			    BPF_PROG_TYPE_SK_SKB, &obj, &parse_prog);
	if (err) {
		printf("Failed to load SK_SKB parse prog\n");
		goto out_sockmap;
	}

	err = bpf_prog_load(SOCKMAP_TCP_MSG_PROG,
			    BPF_PROG_TYPE_SK_MSG, &obj, &msg_prog);
	if (err) {
		printf("Failed to load SK_SKB msg prog\n");
		goto out_sockmap;
	}

	err = bpf_prog_load(SOCKMAP_VERDICT_PROG,
			    BPF_PROG_TYPE_SK_SKB, &obj, &verdict_prog);
	if (err) {
		printf("Failed to load SK_SKB verdict prog\n");
		goto out_sockmap;
	}

	bpf_map_rx = bpf_object__find_map_by_name(obj, "sock_map_rx");
	//if (IS_ERR(bpf_map_rx)) {
	//	printf("Failed to load map rx from verdict prog\n");
	//	goto out_sockmap;
	//}

	map_fd_rx = bpf_map__fd(bpf_map_rx);
	if (map_fd_rx < 0) {
		printf("Failed to get map rx fd\n");
		goto out_sockmap;
	}

	bpf_map_tx = bpf_object__find_map_by_name(obj, "sock_map_tx");
	//if (IS_ERR(bpf_map_tx)) {
	//	printf("Failed to load map tx from verdict prog\n");
	//	goto out_sockmap;
	//}

	map_fd_tx = bpf_map__fd(bpf_map_tx);
	if (map_fd_tx < 0) {
		printf("Failed to get map tx fd\n");
		goto out_sockmap;
	}

	bpf_map_msg = bpf_object__find_map_by_name(obj, "sock_map_msg");
	//if (IS_ERR(bpf_map_msg)) {
	//	printf("Failed to load map msg from msg_verdict prog\n");
	//	goto out_sockmap;
	//}

	map_fd_msg = bpf_map__fd(bpf_map_msg);
	if (map_fd_msg < 0) {
		printf("Failed to get map msg fd\n");
		goto out_sockmap;
	}

	bpf_map_break = bpf_object__find_map_by_name(obj, "sock_map_break");
	//if (IS_ERR(bpf_map_break)) {
	//	printf("Failed to load map tx from verdict prog\n");
	//	goto out_sockmap;
	//}

	map_fd_break = bpf_map__fd(bpf_map_break);
	if (map_fd_break < 0) {
		printf("Failed to get map tx fd\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(parse_prog, map_fd_rx,
		      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		printf("Failed stream parser bpf prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(verdict_prog, map_fd_rx,
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		printf("Failed stream verdict bpf prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(msg_prog, map_fd_msg, BPF_SK_MSG_VERDICT, 0);
	if (err) {
		printf("Failed msg verdict bpf prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(verdict_prog, map_fd_rx,
			      __MAX_BPF_ATTACH_TYPE, 0);
	if (!err) {
		printf("Attached unknown bpf prog\n");
		goto out_sockmap;
	}

	/* Test map update elem afterwards fd lives in fd and map_fd */
	for (i = 2; i < 6; i++) {
		err = bpf_map_update_elem(map_fd_rx, &i, &sfd[i], BPF_ANY);
		if (err) {
			printf("Failed map_fd_rx update sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_update_elem(map_fd_tx, &i, &sfd[i], BPF_ANY);
		if (err) {
			printf("Failed map_fd_tx update sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Test map delete elem and remove send/recv sockets */
	for (i = 2; i < 4; i++) {
		err = bpf_map_delete_elem(map_fd_rx, &i);
		if (err) {
			printf("Failed delete sockmap rx %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_delete_elem(map_fd_tx, &i);
		if (err) {
			printf("Failed delete sockmap tx %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Put sfd[2] (sending fd below) into msg map to test sendmsg bpf */
	i = 0;
	err = bpf_map_update_elem(map_fd_msg, &i, &sfd[2], BPF_ANY);
	if (err) {
		printf("Failed map_fd_msg update sockmap %i\n", err);
		goto out_sockmap;
	}


	/* Test map send/recv */
	for (i = 0; i < 2; i++) {
		buf[0] = i;
		buf[1] = 0x5;
		sc = send(sfd[2], buf, 20, 0);
		if (sc < 0) {
			printf("Failed sockmap send\n");
			goto out_sockmap;
		}

		FD_ZERO(&w);
		FD_SET(sfd[3], &w);
		to.tv_sec = 1;
		to.tv_usec = 0;
		s = select(sfd[3] + 1, &w, NULL, NULL, &to);
		if (s == -1) {
			perror("Failed sockmap select()");
			goto out_sockmap;
		} else if (!s) {
			printf("Failed sockmap unexpected timeout\n");
			goto out_sockmap;
		}

		if (!FD_ISSET(sfd[3], &w)) {
			printf("Failed sockmap select/recv\n");
			goto out_sockmap;
		}

		rc = recv(sfd[3], buf, sizeof(buf), 0);
		if (rc < 0) {
			printf("Failed sockmap recv\n");
			goto out_sockmap;
		}
	}

	/* Negative null entry lookup from datapath should be dropped */
	buf[0] = 1;
	buf[1] = 12;
	sc = send(sfd[2], buf, 20, 0);
	if (sc < 0) {
		printf("Failed sockmap send\n");
		goto out_sockmap;
	}

	/* Push fd into same slot */
	i = 2;
	err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_NOEXIST);
	if (!err) {
		printf("Failed allowed sockmap dup slot BPF_NOEXIST\n");
		goto out_sockmap;
	}

	err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_ANY);
	if (err) {
		printf("Failed sockmap update new slot BPF_ANY\n");
		goto out_sockmap;
	}

	err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_EXIST);
	if (err) {
		printf("Failed sockmap update new slot BPF_EXIST\n");
		goto out_sockmap;
	}

	/* Delete the elems without programs */
	for (i = 2; i < 6; i++) {
		err = bpf_map_delete_elem(fd, &i);
		if (err) {
			printf("Failed delete sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
		}
	}

	/* Test having multiple maps open and set with programs on same fds */
	err = bpf_prog_attach(parse_prog, fd,
			      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		printf("Failed fd bpf parse prog attach\n");
		goto out_sockmap;
	}
	err = bpf_prog_attach(verdict_prog, fd,
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		printf("Failed fd bpf verdict prog attach\n");
		goto out_sockmap;
	}

	for (i = 4; i < 6; i++) {
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_ANY);
		if (!err) {
			printf("Failed allowed duplicate programs in update ANY sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_NOEXIST);
		if (!err) {
			printf("Failed allowed duplicate program in update NOEXIST sockmap  %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_EXIST);
		if (!err) {
			printf("Failed allowed duplicate program in update EXIST sockmap  %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Test tasks number of forked operations */
	for (i = 0; i < tasks; i++) {
		pid[i] = fork();
		if (pid[i] == 0) {
			for (i = 0; i < 6; i++) {
				bpf_map_delete_elem(map_fd_tx, &i);
				bpf_map_delete_elem(map_fd_rx, &i);
				bpf_map_update_elem(map_fd_tx, &i,
						    &sfd[i], BPF_ANY);
				bpf_map_update_elem(map_fd_rx, &i,
						    &sfd[i], BPF_ANY);
			}
			exit(0);
		} else if (pid[i] == -1) {
			printf("Couldn't spawn #%d process!\n", i);
			exit(1);
		}
	}

	for (i = 0; i < tasks; i++) {
		int status;

		assert(waitpid(pid[i], &status, 0) == pid[i]);
		assert(status == 0);
	}

	err = bpf_prog_detach(map_fd_rx, __MAX_BPF_ATTACH_TYPE);
	if (!err) {
		printf("Detached an invalid prog type.\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(map_fd_rx, BPF_SK_SKB_STREAM_PARSER);
	if (err) {
		printf("Failed parser prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(map_fd_rx, BPF_SK_SKB_STREAM_VERDICT);
	if (err) {
		printf("Failed parser prog detach\n");
		goto out_sockmap;
	}

	/* Test map close sockets and empty maps */
	for (i = 0; i < 6; i++) {
		bpf_map_delete_elem(map_fd_tx, &i);
		bpf_map_delete_elem(map_fd_rx, &i);
		close(sfd[i]);
	}
	close(fd);
	close(map_fd_rx);
	bpf_object__close(obj);
	return;
out:
	for (i = 0; i < 6; i++)
		close(sfd[i]);
	printf("Failed to create sockmap '%i:%s'!\n", i, strerror(errno));
	exit(1);
out_sockmap:
	for (i = 0; i < 6; i++) {
		if (map_fd_tx)
			bpf_map_delete_elem(map_fd_tx, &i);
		if (map_fd_rx)
			bpf_map_delete_elem(map_fd_rx, &i);
		close(sfd[i]);
	}
	close(fd);
	exit(1);
}

#define DECLARE
#include "tests.h"
#undef DECLARE

int main(void)
{
	srand(time(NULL));
	test_sockmap(0, NULL);

	return 0;
}

