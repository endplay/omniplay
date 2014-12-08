# OMNIPLAY

## Get the software

### Install Ubuntu 12.04.2 LTS 32-bit

Omniplay runs on the 12.04.2 LTS Ubuntu Linux 32-bit distribution.  You should install
this distro before proceeeding.
The ISO file is available at: http://old-releases.ubuntu.com/releases/12.04.2/ubuntu-12.04.2-desktop-i386.iso.

### Obtain the Omniplay source code

Just clone the GitHub repository:

    $ git clone https://github.com/endplay/omniplay.git 

This will create a number of sub-directories that contain the user-level and kernel source
for omniplay.

## Build and install

Assuming that `<omniplay>` is the root directory where you installed the source:

### One-time setup

    $ cd <omniplay>/scripts
    $ ./setup.sh
    $ source $HOME/.omniplay_setup

## Build the Omniplay kernel 

There are two methods:

Option 1:

    $ cd $OMNIPLAY_DIR/linux-lts-quantal-3.5.0
    $ # The following two setps need be done only once
    $ wget http://web.eecs.umich.edu/~ddevec/omniplay.config
    $ mv omniplay.config .config
    $ # End once only steps
    $ ./compile
    $ sudo reboot

Option 2:

    $ cd $OMNIPLAY_DIR/linux-lts-quantal-3.5.0
    $ make menuconfig
    $ sudo make modules_install
    $ sudo make install
    $ sudo make headers_install INSTALL_HDR_PATH=$OMNIPLAY_DIR/test/replay_headers
    $ sudo reboot

After rebooting, you should be running the Omniplay kernel.
        
### Build glibc

Install dependencies:

    $ sudo apt-get install gawk texinfo autoconf gettext

Configure and build:

    $ cd $OMNIPLAY_DIR/eglibc-2.15/
    $ mkdir build
    $ mkdir prefix
    $ cd build
    $ ../configure --prefix=$OMNIPLAY_DIR/eglibc-2.15/prefix --disable-profile --enable-add-on --without-gd --without-selinux --without-cvs --enable-kernel=3.2.0
    $ make
    $ mkdir /var/db
    $ chown <user> /var/db
    $ touch ../prefix/etc/ld.so.conf
    $ make install

This installs the Omniplay glibc in `eglibc-2.15/prefix`.  This is a bit
of a kludge that allows us to develop code with the standard glibc and
test with the Omniplay glibc.  There are a few complications, though,
that we need to fix:

    $ cd $OMNIPLAY_DIR/eglibc-2.15/prefix
    $ ln -s /usr/lib/locale

### Build the tools

    $ cd $OMNIPLAY_DIR/test/dev
    $ make
    $ cd ..
    $ make

## Record and replay

After each reboot, you need to load the Omniplay kernel module and do some setup work.

Preferred method:

    $ $OMNIPLAY_DIR/scripts/insert_spec.sh

Basic method:

    $ cd $OMNIPLAY_DIR/test
    $ ./setup.sh

Now you can record programs.  You will need to know your dynamic link path.  You can
look in `/etc/ld.so.conf.d/` to figure this out.  A typical path might be:
`/lib/i386-linux-gnu:/usr/lib/i386-linux-gnu:/usr/local/lib:/usr/lib:/lib`

One you determine this, you can record a program by knowing its fully-qualified pathname

    $ ./launcher --pthread <omniplay>/eglibc-2.15/prefix/lib:<libpath> <fq program> <args>

This will record the execution of that program, as well as any children spawned by that program.
So, an easy way to record programs is just to launch a shell that is replayed.  Anything started
from that shell will also  be replayed:

    $ ./launcher --pthread <omniplay>/eglibc-2.15/prefix/lib:<libpath> /bin/bash

You should now see that the following directories are being populated:

`/replay_logdb`: 

This contains the logs of non-determinism plus the initial
checkpoints.  Each directory is a separate replay group named with an
id that increments over time.  Within each directory you should see
`klog*` files (which are kernel-level nondeterminism), `ulog*` files
(which are user-level nondeterminism) and `ckpt` files (the initial
checkpoints).

A new replay group is created on each successful exec.  The replay
group contains all threads and processes spawned by the execed process
(up to the point where they do execs and start new replay groups)

`/replay_cache`: 

This is a copy-on-read cache of file data.  Cache files are named by
device and inode number.  If a file changes over time, past versions
are additionally named by their respective modification times.

You can replay a given group with id `<id>` as follows:

    $ ./resume /replay_logdb/rec_<id> --pthread <omniplay>/src/omniplay/eglibc-2.15/prefix/lib

Keep in mind that a recording process can not initiate a replay.  So,
do this from some shell other than the recording bash shell that you
started above.  Also, a recording must finish in order for you to
replay it successfully.

A successful replay will print the message "Goodbye, cruel lamp! This
replay is over" in the kernel log (use dmesg to check).  An
unsuccessful replay may or may not print this message.  It will also
print out error messages in any event.

If you would like a simpler way to replay all groups from id `<m>` to `<n>`, try:

    $ ./testall.py <m> <n>

(omitting the last `<n>` argument replays everything from `m` onward).   The replaying
will stop if any replay was unsuccessful.

## Debugging and tools

Use parseklog to examine a kernel log.

    $ omniplay/test/parseklog /tmp/logs/klog.id.* > parsed_klog

Use the user-level debug log.
Turn on the USE_DEBUG_LOG macro in `eglibc-2.15/nptl/pthread_log.h` and `linux-lts-quantal-3.5.0/include/linux/replay.h`


## How to build packages:

Find the package for the executable you want to debug

    $ dpkg -S <fully-qualified pathname>

Get the source for that package

    $ sudo apt-get source <package>

Get build dependencies:

    $ sudo apt-get build-dep <package>

If you need to build with debug symbols, add the following to environment

    $ export DEB_BUILD_OPTIONS="debug nostrip noopt"

Build the package as is

    $ dpkg-buildpackage -us -uc -nc

Build the package with the changes you made

    $ debuild -us -uc -b

Install the packages you build

    $ sudo dpkg -i ../*foo*.deb


## Replaying with Pin

Download Pin version 2.13 from:
http://software.intel.com/en-us/articles/pintool-downloads

The Pin tools are in the folder, `pin_tools`.
To build:

    $ cd omniplay/pin_tools
    $ make PIN_ROOT=<pin_root>

where `pin_root` is the location where you untar'ed the Pin folder from the download above.

In order to replay with Pin, we need extra information about the
memory maps that the program will use. We can either save this
information on when a process is being recorded or replayed.

To record a process and save the mmaps:

    $ launcher -m <prog>

If you didn't record the mmaps are record time, replay a process and
save the mmaps:

    $ resume <dir> -m

It will save a file called `mlog` containing the list of mmaps
(`test/parsemlog.c` should parse the mlog).

Then, replay with pin:

    $ resume <dir> -p

The replay will pause and will resume when Pin is attached.

Attach Pin (the full path for the tool is needed):

    $ /home/mcchow/pin-2.13/pin -pid <pid> -t /home/mcchow/omniplay/pin_tools/obj-ia32/print_instructions.so
