#include "Shared.h"
void ResolveIP(u32 ip, char* output) {
	uint8_t byte1 = ip>>24&0xff;
	uint8_t byte2 = ip>>16&0xff;
	uint8_t byte3 = ip>>8&0xff;
	uint8_t byte4 = ip&0xff;
	snprintf(output, 16, "%d.%d.%d.%d", byte1, byte2, byte3, byte4);
}

