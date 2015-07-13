#!/bin/bash

portscan()
{
	if [ "$1" = "TCP" ]; then
		option = "-PR"
	else
		option = "-sU"
	fi
								
	echo "$1 port scan start at `date`"
	for((k=1;k<=10;k++))
	do
		nmap -v $option $2
	done
	echo "$1 port scan end at `date`"
}
target="192.168.6.1"
portscan "TCP" $target
portscan "UDP" $target

