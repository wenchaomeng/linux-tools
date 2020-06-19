DIR=/sys/fs/cgroup/bpf
if [ ! -d  $DIR ];then
	echo $DIR not exist, create it
	sudo mkdir /sys/fs/cgroup/bpf
fi
