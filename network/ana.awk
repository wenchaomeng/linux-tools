BEGIN{
	maxkeep1=0;
	maxkeep5=0;
	maxkeep10=0;
	firtotal=0;firretrans=0;
	lasttotal=0;lastretrans=0;
}
/segments/{
	if(firtotal == 0){
		firtotal=$1;
		firretrans=$5
		print firtotal, firretrans;
	}
	lasttotal=$1
	lastretrans=$5
}
/^\./{
	total++;
	if($1 > 1){
		print "error percent:" $1
	}
	if($1 > max){
		max = $1;
	}
	if($1>=0.01){
		p1++; 
		keep1++;
		if($1>0.05){
			p5++;
			keep5++;
			if($1>0.30){
				p10++;
				keep10++;
			}
	 	}
		if(keep1 > maxkeep1){
			maxkeep1 = keep1;
		}
		if(keep5 > maxkeep5){
			maxkeep5 = keep5;
		}
		if(keep10 > maxkeep10){
			maxkeep10 = keep10;
		}
	}else{
		keep1=0;
		keep5=0;
		keep10=0;
	} 
}
END{
	print total, "day:", total/86400;
	print "max:", max;
	print "avg:", (lastretrans-firretrans)/(lasttotal-firtotal);
	print ">=0.01", p1/total;
	print ">=0.05", p5/total;
	print ">=0.10", p10/total;
	print "keep1", maxkeep1, "s", maxkeep1/60, "min";
	print "keep5", maxkeep5, "s", maxkeep5/60, "min";
	print "keep10", maxkeep10, "s", maxkeep10/60, "min";
}
