sudo service redis stop
./init_cgroup.sh
pid=`ps -ef | egrep redis-[s]erver | awk '{print $2}'`
if [ -n "$pid" ];then
	echo redis pid: $pid not empty!!
	if egrep $pid /sys/fs/cgroup/bpf/cgroup.procs;then
		echo already  exists in cgroup!
		exit
	fi
	echo redis $pid not in cgroup, kill it!!
	kill -TERM $pid
	sleep 3
fi
echo $$ | sudo tee -a /sys/fs/cgroup/bpf/cgroup.procs
nohup redis-server > redis.log & 
sleep 3
pid=`ps -ef | egrep redis-[s]erver | awk '{print $2}'`
if [ -z "$pid" ];then
	echo FAIL: started redis-server faliled
	exit
fi
if egrep $pid /sys/fs/cgroup/bpf/cgroup.procs;then
	echo redis $pid in cgroup!
else
	echo FAIL: redis pid not in cgroup, check
fi
