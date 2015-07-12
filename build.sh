#!/bin/bash
#$cd=`which chdir`
_help()
{
	echo "Usage: $1 [make|clean]"
}
_make()
{
	#generate theadpool dynamic link library
	cd threadpool
	make
	
	#build plugins
	cd ../plugin
	make
	
	cd  ..
	make
}
_clean()
{
	cd threadpool
	make clean

	cd ../plugin
	make clean

	cd ..
	make distclean
}

_main()
{
	if [ "$1" = "make" ]; then
		_make	
	elif [ "$1" = "clean" ]; then
		_clean	
	else
		_help $0
		exit 1
	fi
	exit 0
}

_main $1
