#include "FileFilerDriver.h"
#include <ntifs.h>

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT  pDriverObject) {

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = DispatchPassDown;

	pDriverObject->MajorFunction[IRP_MJ_WRITE] = FilterWrite;

	AttachToFileSystemStack(pDriverObject);
	return STATUS_SUCCESS;
}

VOID Unload(IN PDRIVER_OBJECT pDriverObject) {
	IoDetachDevice(pDriverObject->DeviceObject->NextDevice);
	IoDeleteDevice(pDriverObject->DeviceObject);
}