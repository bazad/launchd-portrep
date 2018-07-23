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

#endif
