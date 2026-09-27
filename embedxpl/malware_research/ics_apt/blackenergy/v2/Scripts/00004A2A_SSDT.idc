#include <idc.idc>
static main (void) {
	MakeDword(0xff0d20c3);
	MakeName(0xff0d20c3, "FakeNtOpenKey");
	MakeDword(0xff0d2617);
	MakeName(0xff0d2617, "FakeNtProtectVirtualMemory");
	MakeDword(0xff0d2397);
	MakeName(0xff0d2397, "FakeNtSetValueKey");
	MakeDword(0xff0d2267);
	MakeName(0xff0d2267, "FakeNtEnumerateValueKey");
	MakeDword(0xff0d25c1);
	MakeName(0xff0d25c1, "FakeNtWriteVirtualMemory");
	MakeDword(0xff0d2070);
	MakeName(0xff0d2070, "FakeNtSetContextThread");
	MakeDword(0xff0d1da0);
	MakeName(0xff0d1da0, "FakeNtQuerySystemInformation");
	MakeDword(0xff0d256b);
	MakeName(0xff0d256b, "FakeNtReadVirtualMemory");
	MakeDword(0xff0d1e93);
	MakeName(0xff0d1e93, "FakeNtOpenProcess");
	MakeDword(0xff0d1fca);
	MakeName(0xff0d1fca, "FakeNtTerminateThread");
	MakeDword(0xff0d216b);
	MakeName(0xff0d216b, "FakeNtEnumerateKey");
	MakeDword(0xff0d2487);
	MakeName(0xff0d2487, "FakeNtDeleteValueKey");
	MakeDword(0xff0d1f0b);
	MakeName(0xff0d1f0b, "FakeNtOpenThread");
	MakeDword(0xff0d201d);
	MakeName(0xff0d201d, "FakeNtSuspendThread");
}