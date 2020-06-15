sudo service redis stop
echo $$ | sudo tee -a /sys/fs/cgroup/bpf/cgroup.procs
nohup redis-server > redis_log & 
sleep 3
echo read from "/sys/fs/cgroup/bpf/cgroup.procs"
cat /sys/fs/cgroup/bpf/cgroup.procs
