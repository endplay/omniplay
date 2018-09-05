#!/bin/bash


if [[ $(whoami) -ne "root" ]]; then
    echo "Must be run as root!"
    exit 1
fi

user=$(who am i | awk '{print $1}')


custom_omniplay=0
omniplay_dir="`pwd`"
length=${#omniplay_dir}
newlen=$(($length-8))
substr=${omniplay_dir:0:$newlen}
omniplay_dir=$substr

TEMP=$(getopt -o :d:h --long help,uninstall,path,dir: -n 'setup.sh' -- $@)

eval set -- "$TEMP"

uninstall=0
do_path=0


function print_usage() {
	echo "Usage: $1 [options]" 
	echo "Options include:"
	echo "    -h,--help - display this message"
	echo "    --uninstall - Uninstall the testmachinecontrol environment"
	echo "    --dir=<omniplay_dir> -d <omniplay_dir> - Install with OMNIPLAY_DIR different than $omniplay_dir"
#	echo "    --spec      - Insert the spec.ko module by default when you log in."
	echo "    --path      - Add OMNIPLAY_DIR/test to your path"
}

while true; do
	case "$1" in
		-h | --help ) print_usage $0; exit 0 ;;
		--dir | -d ) omniplay_dir="$2"; custom_omniplay=1; shift 2 ;;
		--uninstall ) uninstall=1; shift ;;
#		--spec ) do_spec=1; shift ;;
		--path ) do_path=1; shift ;;
		-- ) shift; break ;;
		* ) break ;;
	esac
done

if [[ "$#" -gt "0" ]]; then
	print_usage $0
	exit 1
fi

setupfile=$(sudo -H -u $user echo $HOME/.omniplay_setup)

if [ ! -d $omniplay_dir/scripts ] || [ ! -d $omniplay_dir/linux-lts-quantal-3.5.0 ] || [ ! -e $omniplay_dir/scripts/setup.sh ] || [ ! -e $omniplay_dir/scripts/common.sh ]; then
	echo "$omniplay_dir doesn't appear to be your omniplay directory, please run this script from your omniplay/scripts directory, or specify your OMNIPLAY_DIR with -d"
	exit 1
fi


if [[ "$uninstall" -ne "0" ]]; then
	if [[ -z $OMNIPLAY_DIR ]]; then
		echo "omniplay doesn't appear to be installed"
		exit 0
	fi

	sudo -H -u $user cat $HOME/.bashrc | sed -e "s|source $setupfile||" > $HOME/.bashrc_tmp
	sudo -H -u $user mv $HOME/.bashrc_tmp $HOME/.bashrc
	rm -f $setupfile

	exit 0
fi

echo "Creating/updating setup file: $setupfile"
sudo -H -u $user echo "export OMNIPLAY_DIR=$omniplay_dir" > $setupfile
echo "export PYTHONPATH=\$PYTHONPATH:\$OMNIPLAY_DIR/python_environ" >> $setupfile

egrep ^spec$ /etc/modules >/dev/null 

if [[ "$?" != 0 ]]; then
    echo "spec" >> /etc/modules
fi

if [[ "$do_path" -eq "1" ]]; then
	echo "$PATH=$PATH:$omniplay_dir/test" >> $setupfile
fi

cat $HOME/.bashrc | grep "source $setupfile" || {
	echo "Inserting line into bashrc to source setupfile"
	echo "source $setupfile" >> $HOME/.bashrc
}

echo "Please execute \"source $setupfile\" to finish installation"
