#!/bin/sh

export FORCE_NET_VERBOSE=1
export FORCE_NET_FLOWINFO=0x7812345

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

#gdb ./test_client6
#valgrind -v --db-attach=yes ./test_client6 "${@}"
strace -o ${0}.strace -x -f -s200 ./test_client6 "${@}"
