#!/bin/sh

export FORCE_NET_TOS="0x0f"

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

strace -o test_tos1.strace -f -s100 ./test_bind "$@"
