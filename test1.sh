#!/bin/sh

export FORCE_BIND_ADDRESS=127.0.0.2

# use -1 to not change port
export FORCE_BIND_PORT=900

export LD_PRELOAD="${LD_PRELOAD}:./force_bind.so"

exec "$@"
