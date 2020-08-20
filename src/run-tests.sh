#!/bin/sh
for t in $(cat testlist); do
	
	echo "Running $t ... "
	"./$t"
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "OK";
	else
		echo "FAIL: $ret"
	fi
done
