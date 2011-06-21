#!/bin/sh

export FORCE_BIND_ADDRESS_V4=127.0.0.2

# use -1 to not change port
export FORCE_BIND_PORT_V4=900

export LD_PRELOAD="${LD_PRELOAD}:/usr/lib/force_bind.so"

exec "$@"
