#!/usr/bin/env bash
# usage: cross-test-ssh.sh [--ssh SSH] HOST COMMAND ...
# Run with --help flag to get more detailed help.

progname="$(basename $0)"
env_blacklist='HOME LOGNAME MAIL PATH SHELL SHLVL SSH_CLIENT SSH_CONNECTION USER TERM TERMCAP PWD'

usage="usage: ${progname} [--ssh SSH] HOST COMMAND ..."
help="Run an EGLIBC test COMMAND on the remote machine HOST, via ssh,
passing environment variables, preserving the current working directory,
and respecting quoting.

If the '--ssh SSH' flag is present, use SSH as the SSH command,
instead of ordinary 'ssh'.

To use this to run EGLIBC tests, invoke the tests as follows:

  $ make cross-test-wrapper='ABSPATH/cross-test-ssh.sh HOST' tests

where ABSPATH is the absolute path to this script, and HOST is the
name of the machine to connect to via ssh.

If you need to connect to the test machine as a different user, you
may specify that just as you would to SSH:

  $ make cross-test-wrapper='ABSPATH/cross-test-ssh.sh USER@HOST' tests

Naturally, the remote user must have an appropriate public key, and
you will want to ensure that SSH does not prompt interactively for a
password on each connection.

HOST and the build machines (on which 'make check' is being run) must
share a filesystem; all files needed by the tests must be visible at
the same paths on both machines.

${progname} runs COMMAND in the same directory on the HOST that
${progname} itself is run in on the build machine.

The command and arguments are passed to the remote host in a way that
avoids any further shell substitution or expansion, on the assumption
that the shell on the build machine has already done them
appropriately.

${progname} propagates the values all environment variables through to
the remote target, except the following:
${env_blacklist}"

ssh='ssh'
while true; do
    case "$1" in

        "--ssh")
            shift; ssh="$1"
            ;;

        "--help")
            echo "$usage"
            echo "$help"
            exit 0
            ;;

        *)
            break
            ;;
    esac
    shift
done

if [ $# -lt 1 ]; then
    echo "$usage" >&2
    echo "Type '${progname} --help' for more detailed help." >&2
    exit 1
fi

host="$1"; shift

# Return all input as a properly quoted Bourne shell string.
bourne_quote () {
    printf '%s' '"'
    sed -n \
        -e '1h' \
        -e '2,$H' \
        -e '${g
              s/["$\`]/\\&/g
              p
             }'
    printf '%s' '"'
}

# Remove unnecessary newlines from a Bourne shell command sequence.
remove_newlines () {
    sed -n \
        -e '1h' \
        -e '2,$H' \
        -e '${g
              s/\([^\]\)\n/\1; /g
              p
             }'
}

# Unset all variables from the blacklist.  Then echo all exported
# variables.  This should be run in a subshell.  The 'export -p'
# command adds backslashes for environment variables which contain
# newlines.
blacklist_exports () {
    local var
    for var in ${env_blacklist}; do
	unset $var
    done
    export -p
}

# Produce properly quoted Bourne shell arguments for 'env' to carry
# over the current environment, less blacklisted variables.
exports="$( (blacklist_exports) | sed -e 's|^declare -x |export |')"

# Transform the current argument list into a properly quoted Bourne shell
# command string.
command="$(for word in "$@"; do
               printf '%s' "$word" | bourne_quote
               printf '%s' ' '
           done)"

# Add commands to set environment variables and the current directory.
command="${exports}
cd $PWD
${command}"

# HOST's sshd simply concatenates its arguments with spaces and
# passes them to some shell.  We want to force the use of /bin/sh,
# so we need to re-quote the whole command to ensure it appears as
# the sole argument of the '-c' option.
$ssh "$host" /bin/sh -c "$(printf '%s\n' "${command}" | bourne_quote | remove_newlines)"
