#ifndef LAUNCHD_PORTREP__LAUNCHD_PORTREP_HOSTPRIV_H_
#define LAUNCHD_PORTREP__LAUNCHD_PORTREP_HOSTPRIV_H_

#include <mach/mach.h>
#include <stdbool.h>

/*
 * launchd_portrep_host_priv
 *
 * Description:
 * 	Use the launchd-portrep vulnerability to obtain the host-priv port.
 *
 * Returns:
 * 	Returns the host-priv port on success and MACH_PORT_NULL on failure.
 */
mach_port_t launchd_portrep_host_priv(void);

/*
 * host_priv_task_for_pid
 *
 * Description:
 * 	A task_for_pid implementation using the host_priv port.
 *
 * Parameters:
 * 	host_priv			The host-priv port.
 * 	pid				The PID of the process.
 *
 * Returns:
 * 	Returns the task port for the specified process on success and MACH_PORT_NULL on failure.
 */
mach_port_t host_priv_task_for_pid(mach_port_t host_priv, int pid);

/*
 * launchd_start_service
 *
 * Description:
 * 	Try to start the specified service with launchd.
 *
 * Parameters:
 * 	service_name			The name of the service to start.
 * 	wait				Whether this function to wait for a reply before returning.
 *
 * Returns:
 * 	Returns true if the service was successfully looked up and a Mach message sent.
 */
bool launchd_start_service(const char *service_name, bool wait);

/*
 * launchd_portrep_hostpriv_log
 *
 * Description:
 * 	This is the log handler that will be executed when launchd-portrep-hostpriv wants to log a
 * 	message. The default implementation logs the message to stderr. Setting this value to NULL
 * 	will disable all logging. Specify a custom log handler to process log messages in another
 * 	way.
 *
 * Parameters:
 * 	type				A character representing the type of message that is being
 * 					logged.
 * 	format				A printf-style format string describing the error message.
 * 	ap				The variadic argument list for the format string.
 *
 * Log Type:
 * 	The type parameters is one of:
 * 	- D: Debug:     Used for debugging messages. Set the DEBUG build variable to control debug
 * 	                verbosity.
 * 	- I: Info:      Used to convey general information about the exploit or its progress.
 * 	- W: Warning:   Used to indicate that an unusual but recoverable condition was encountered.
 * 	- E: Error:     Used to indicate that an unrecoverable error was encountered.
 * 	                launchd-portrep-hostpriv  might continue running after an error was
 * 	                encountered, but it probably will not succeed.
 */
extern void (*launchd_portrep_hostpriv_log)(char type, const char *format, va_list ap);

#endif
