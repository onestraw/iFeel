#!/bin/sh
#generate theadpool dynamic link library
cd threadpool
make

#build plugins
cd ../plugin
make
