#include "launchd-portrep.h"

#include <stdio.h>

int main() {
	// Replace launchd's send right to powerd with a fake service port.
	const char *POWERD_SERVICE_NAME = "com.apple.PowerManagement.control";
	mach_port_t real_powerd, fake_powerd;
	bool ok = launchd_replace_service_port(POWERD_SERVICE_NAME, &real_powerd, &fake_powerd);
	if (!ok) {
		return 1;
	}
	printf("real_powerd = %x, fake_powerd = %x\n", real_powerd, fake_powerd);
	return 0;
}
