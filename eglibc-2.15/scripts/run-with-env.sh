#!/bin/sh
# Usage: run-with-env.sh CMD ...
# Execute commands with environment variables set at the last minute.
# For certain environment variable whose names are of the form
# 'EGLIBC_TEST_foo', if they are set, we set an environment variable
# 'foo' to their value.
#
# This lets us run test programs via wrappers with environment
# variable settings that would otherwise interfere with the wrapper
# itself, like LD_PRELOAD or LD_AUDIT.

if [ "${EGLIBC_TEST_LD_PRELOAD+set}" ]; then
    export LD_PRELOAD="${EGLIBC_TEST_LD_PRELOAD}"
fi

if [ "${EGLIBC_TEST_LD_AUDIT+set}" ]; then
    export LD_AUDIT="${EGLIBC_TEST_LD_AUDIT}"
fi

if [ "${EGLIBC_TEST_LD_LIBRARY_PATH+set}" ]; then
    export LD_LIBRARY_PATH="${EGLIBC_TEST_LD_LIBRARY_PATH}"
fi

exec "$@"
