

ltotal=0
lretrans=0
while :
do
	tcpstat=`netstat -s | egrep Tcp: -A 10 | egrep "send out|retrans"`
	echo $tcpstat `date`
	total=`echo $tcpstat | egrep "send out" | awk '{print $1}'`
	retrans=`echo $tcpstat | egrep "trans" | awk '{print $5}'`
	if [ ! $ltotal -eq 0 ];then
		dtotal=$(($total-$ltotal))
		dretrans=$(($retrans-$lretrans))
		echo "scale=8;$dretrans/$dtotal" | bc
	fi
	
	ltotal=$total
	lretrans=$retrans
	sleep 1
done

