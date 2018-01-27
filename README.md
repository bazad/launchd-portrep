# launchd-portrep

<!-- Brandon Azad -->

launchd-portrep is an exploit for a port replacement vulnerability in launchd, the initial
userspace process and service management daemon on macOS. By sending a crafted Mach message to the
bootstrap port, launchd can be coerced into deallocating its send right for any Mach port to which
the attacker also has a send right. This allows the attacker to impersonate any launchd service it
can look up to the rest of the system.


## The vulnerability

Launchd multiplexes multiple different Mach message handlers over its main port, including a MIG
handler for exception messages. If a process sends a `mach_exception_raise` or
`mach_exception_raise_state_identity` message to its own bootstrap port, launchd will receive and
process that message as a host-level exception.

Unfortunately, launchd's handling of these messages is buggy. If the exception type is `EXC_CRASH`,
then launchd will deallocate the thread and task ports sent in the message and then return
`KERN_FAILURE` from the service routine, causing the MIG system to deallocate the thread and task
ports again. (The assumption is that if a service routine returns success, then it has taken
ownership of all resources in the Mach message, while if the service routine returns an error, then
it has taken ownership of none of the resources.)

Here is the code from launchd's service routine for `mach_exception_raise` messages, decompiled
using IDA/Hex-Rays and lightly edited for readability:

```c
kern_return_t __fastcall
catch_mach_exception_raise(                             // (a) The service routine is
        mach_port_t           exception_port,           //     called with values directly
        mach_port_t           thread,                   //     from the Mach message
        mach_port_t           task,                     //     sent by the client. The
        unsigned int          exception,                //     thread and task ports could
        mach_exception_data_t code,                     //     be arbitrary send rights.
        unsigned int          codeCnt)
{
    kern_return_t kr;      // eax@1 MAPDST
    kern_return_t result;  // eax@10
    int pid;               // [rsp+14h] [rbp-43Ch]@1
    char codes_str[1024];  // [rsp+20h] [rbp-430h]@5
    __int64 __stack_guard; // [rsp+420h] [rbp-30h]@1

    __stack_guard = *__stack_chk_guard_ptr;
    pid = -1;
    kr = pid_for_task(task, &pid);
    if ( kr )
    {
        _os_assumes_log(kr);
        _os_avoid_tail_call();
    }
    if ( codeCnt )
    {
        do
        {
            __snprintf_chk(codes_str, 0x400uLL, 0, 0x400uLL, "0x%llx", *code);
            ++code;
            --codeCnt;
        }
        while ( codeCnt );
    }
    launchd_log_2(
        0LL,
        3LL,
        "Host-level exception raised: pid = %d, thread = 0x%x, "
            "exception type = 0x%x, codes = { %s }",
        pid,
        thread,
        exception,
        codes_str);
    kr = deallocate_mach_port(thread);                  // (b) The "thread" port sent in
    if ( kr )                                           //     the message is deallocated.
    {
        _os_assumes_log(kr);
        _os_avoid_tail_call();
    }
    kr = deallocate_mach_port(task);                    // (c) The "task" port sent in the
    if ( kr )                                           //     message is deallocated.
    {
        _os_assumes_log(kr);
        _os_avoid_tail_call();
    }
    result = 0;
    if ( *__stack_chk_guard_ptr == __stack_guard )
    {
        LOBYTE(result) = exception == 10;               // (d) If the exception type is 10
        result *= 5;                                    //     (EXC_CRASH), then an error
    }                                                   //     KERN_FAILURE is returned.
    return result;                                      //     MIG will deallocate the
}                                                       //     ports again.
```

This double-deallocate of the port names is problematic because a process can set any ports it
wants as the task and thread ports in the exception message. Launchd performs no checks that the
received send rights actually correspond to a thread and a task; the ports could, for example, be
send rights to ports already in launchd's IPC space. Then the double-deallocate would actually
cause launchd to drop a user reference on one of its own ports.

This bug can be exploited to free launchd's send right to any Mach port to which the attacking
process also has a send right. In particular, if the attacking process can look up a system service
using launchd, then it can free launchd's send right to that service and then impersonate the
service to the rest of the system. After that there are many different routes to gain system
privileges.


## Exploit strategy

This bug is a less general version of [CVE-2016-7637], a Mach port user reference handling issue in
XNU discovered by Ian Beer that allowed processes to free Mach ports in other processes. Ian Beer
exploited that vulnerability on macOS by replacing launchd's send right to the
`com.apple.CoreServices.coreservicesd` endpoint and impersonating coreservicesd to the rest of the
system. Coreservicesd is an attractive target because it is one of a few services to which clients
will send their task port in a Mach message. By replacing launchd's send right to coreservicesd
with his own port and then triggering privileged clients to look up and communicate with
coreservicesd, he was able to obtain the task port for a privileged process and then execute code
within that process.

[CVE-2016-7637]: https://bugs.chromium.org/p/project-zero/issues/detail?id=959

Since the behavior on macOS hasn't changed, I basically copied Ian Beer's exploit strategy for this
vulnerability. We send exception messages to launchd containing coreservicesd's service port until
we free launchd's send right to that port. We can detect when we've freed the right by calling
`bootstrap_look_up` again on the service: if launchd returns an invalid port name, then we've
successfully freed launchd's send right to the port. Then, we repeatedly register and unregister a
large number of services with launchd until one of the services we register is assigned the same
Mach port name in launchd's IPC space as the original coreservicesd port. At this point, any
process that looks up `com.apple.CoreServices.coreservicesd` in launchd will receive a send right
to our fake service rather than the real coreservicesd. We then run a MITM server on the fake
service port, inspecting all Mach ports in the messages received from clients before sending them
along to the real coreservicesd. Eventually a privileged client will connect and send us its task
port, allowing us to extract the host-priv port. Once we have the host-priv port, we can get the
task port for any task on the system.

In order to (mostly) restore proper functioning of the system, we use the host-priv port to obtain
launchd's task port, and then use launchd's task port to replace launchd's send right to our fake
service port back with a send right to the real coreservicesd. That way future clients can actually
reach coreservicesd.

One problem I've noticed with this approach is that the system seems to hang on shutdown for a
short while. I'm assuming that this is because tampering with launchd's ports messes up some of
launchd's accounting or port notifications. I haven't investigated this issue further, but
restarting coreservicesd using launchctl seems to fix it:

	$ sudo launchctl kickstart -k -p system/com.apple.coreservicesd


## Usage

To build, run `make`. See the top of the Makefile for various build options.

Run the exploit by specifying the target leak size on the command line:

	$ ./launchd-portrep
	[+] Got task port 1df73 for process 1266
	[+] Got host priv port 17537!
	[+] launchd task: 1e2ef
	[+] Fixed up launchd
	[+] We did it :) Yay!

launchd-portrep has been tested on macOS 10.13.4 Beta 17E139j.


## License

The launchd-portrep code is released under the MIT license.


---------------------------------------------------------------------------------------------------

By Brandon Azad
