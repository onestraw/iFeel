#/bin/bash

sites=(
"www.baidu.com"
"www.google.com"
"www.qq.com"
"www.ict.ac.cn"
"www.xueqiu.com"
"weibo.com"
"onestraw.net"
)
for((i=0; i< ${#sites[@]} ; i++)) 
do
	ping "${sites[i]}" -c 1
done
