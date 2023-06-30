#include "stdafx.h"

struct {
	DWORD Length;
	NIC_DRIVER Drivers[0xFF];
} NICs = { 0 };

PDRIVER_DISPATCH DiskControlOriginal = 0, MountControlOriginal = 0, PartControlOriginal = 0, NsiControlOriginal = 0, GpuControlOriginal = 0;


ULONG GenerateKey(ULONG seed)
{
	ULONG key;
	RtlRandomEx(&seed);
	key = seed % 256;
	return key;
}




NTSTATUS PartInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(PARTITION_INFORMATION_EX)) {
			PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.PartitionId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartLayoutIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
			PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.DiskId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_DISK_GET_PARTITION_INFO_EX:
		ChangeIoc(ioc, irp, PartInfoIoc);
		break;
	case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
		ChangeIoc(ioc, irp, PartLayoutIoc);
		break;
	}

	return PartControlOriginal(device, irp);
}

NTSTATUS StorageQueryIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
			PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;
			ULONG offset = desc->SerialNumberOffset;
			if (offset && offset < request.BufferLength) {
				strcpy((PCHAR)desc + offset, SERIAL);

			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS AtaPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA)) {
			PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
			ULONG offset = (ULONG)pte->DataBufferOffset;
			if (offset && offset < request.BufferLength) {
				PCHAR serial = (PCHAR)((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset))->SerialNumber;
				SwapEndianess(serial, SERIAL);

			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS SmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(SENDCMDOUTPARAMS)) {
			PCHAR serial = ((PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;
			SwapEndianess(serial, SERIAL);

		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS DiskControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_STORAGE_QUERY_PROPERTY:
		if (StorageDeviceProperty == ((PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer)->PropertyId) {
			ChangeIoc(ioc, irp, StorageQueryIoc);
		}
		break;
	case IOCTL_ATA_PASS_THROUGH:
		ChangeIoc(ioc, irp, AtaPassIoc);
		break;
	case SMART_RCV_DRIVE_DATA:
		ChangeIoc(ioc, irp, SmartDataIoc);
		break;
	}

	return DiskControlOriginal(device, irp);
}


#include <stdlib.h>

ULONG(*RaidEnableDisableFailurePrediction)(PFUNCTIONAL_DEVICE_EXTENSION, BOOLEAN) = 0;
#define IOCTL_RAID_UPDATE_PROPERTIES CTL_CODE(FILE_DEVICE_DISK, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)

VOID RaidControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID(*RaidControlOriginal)(IN PDEVICE_OBJECT, IN PIRP) = 0;


void readshitfile()
{
	// Define the necessary variables
	UNICODE_STRING unicodename;
	OBJECT_ATTRIBUTES attributeobj;
	IO_STATUS_BLOCK ioStatusBlock;
	LARGE_INTEGER byteoffs;
	HANDLE handle;

	// Set the byte offset to 0
	byteoffs.QuadPart = 0;

	// Initialize the Unicode string with the file path
	RtlInitUnicodeString(&unicodename, L"\\SystemRoot\\aci25issad.tmp");

	// Initialize the object attributes with the Unicode string
	InitializeObjectAttributes(&attributeobj, &unicodename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

	// Create a file handle to the file with GENERIC_ALL access
	ZwCreateFile(&handle, GENERIC_ALL, &attributeobj, &ioStatusBlock, 0, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);

	// Read the file into the SERIAL buffer
	ZwReadFile(handle, 0, 0, 0, &ioStatusBlock, SERIAL, 50, &byteoffs, 0);

	// Null terminate the buffer
	SERIAL[49] = 0;

	// Close the file handle
	ZwClose(handle);
}
typedef NTSTATUS(NTAPI* PNEW_CONTROL)(PDEVICE_OBJECT DeviceObject, PIRP Irp);
PNEW_CONTROL NewControl;
PNEW_CONTROL NewControlOriginal;




//NTSTATUS NewControlHook(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//	NTSTATUS status = NewControlOriginal(DeviceObject, Irp);
//	if (Irp->IoStatus.Status == STATUS_SUCCESS)
//	{
//		if (Irp->IoStatus.Information == sizeof(NEW_DISK_CODE))
//		{
//			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, NEW_DISK_CODE, sizeof(NEW_DISK_CODE));
//		}
//	}
//
//	return status;
//}


#define BSWAP16(x) ((x) >> 8) | ((x) << 8)
#define BSWAP32(x) (((x) >> 24) | (((x) >> 8) & 0xff00) | (((x) << 8) & 0xff0000) | ((x) << 24))
#define BSWAP64(x) ((x) >> 56) | (((x) >> 40) & 0xff00) | (((x) >> 24) & 0xff0000) | (((x) >> 8) & 0xff000000) | (((x) << 8) & 0xff00000000) | (((x) << 24) & 0xff0000000000) | (((x) << 40) & 0xff000000000000) | ((x) << 56)
_Function_class_(IO_COMPLETION_ROUTINE)
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS UpdateDiskProperties(PDEVICE_OBJECT disk);

NTSTATUS UpdateDiskProperties(PDEVICE_OBJECT disk) {
	KEVENT event;
	KeInitializeEvent(&event, NotificationEvent, FALSE);

	PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_UPDATE_PROPERTIES, disk, 0, 0, 0, 0, 0, &event, 0);
	if (!irp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	NTSTATUS status;
	if (STATUS_PENDING == (status = IoCallDriver(disk, irp))) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
	}
	return status;
}

NTSTATUS DisableSmart(PFUNCTIONAL_DEVICE_EXTENSION ext, DISK_FAIL_PREDICTION Diskya) {
	return Diskya(ext, FALSE);
}
VOID EncryptDecryptString(PCHAR str, UCHAR key) {
	for (DWORD i = 0; str[i] != '\0'; ++i) {
		str[i] ^= key;
	}
}

VOID ReadSerialNumberFromFile() {
	// Define the necessary variables
	UNICODE_STRING unicodename;
	OBJECT_ATTRIBUTES attributeobj;
	IO_STATUS_BLOCK ioStatusBlock;
	LARGE_INTEGER byteoffs;
	HANDLE handle;

	// Set the byte offset to 0
	byteoffs.QuadPart = 0;

	// Initialize the Unicode string with the file path
	RtlInitUnicodeString(&unicodename, L"\\SystemRoot\\win32ksystem.tmp");

	// Initialize the object attributes with the Unicode string
	InitializeObjectAttributes(&attributeobj, &unicodename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

	// Create a file handle to the file with GENERIC_ALL access
	ZwCreateFile(&handle, GENERIC_ALL, &attributeobj, &ioStatusBlock, 0, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);

	// Read the file into the SERIAL buffer
	ZwReadFile(handle, 0, 0, 0, &ioStatusBlock, SERIAL, 50, &byteoffs, 0);

	// Null terminate the buffer
	SERIAL[49] = 0;

	// Close the file handle
	ZwClose(handle);
}


PDRIVER_DISPATCH g_original_partmgr_control;
PDRIVER_DISPATCH g_original_disk_control;
PDRIVER_DISPATCH g_original_mountmgr_control;

PDRIVER_DISPATCH add_irp_hook(PUNICODE_STRING driver_name, PDRIVER_DISPATCH new_dispatch_function)
{
	PDRIVER_OBJECT driver_object = NULL;
	NTSTATUS status = ObReferenceObjectByName(driver_name, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&driver_object);

	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	PDRIVER_DISPATCH original_dispatch_function = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = new_dispatch_function;

	ObDereferenceObjectWithTag(driver_object, 'tGse');
	return original_dispatch_function;
}

VOID yes() {
	ReadSerialNumberFromFile();
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\volmgr"), PartControl, PartControlOriginal);

	UNICODE_STRING disk_str = RTL_CONSTANT_STRING(L"\\Driver\\disk");
	PDRIVER_OBJECT disk_object = 0;
	NTSTATUS status = ObReferenceObjectByName(&disk_str, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&disk_object);

	if (NT_SUCCESS(status)) {
		AppendSwap(disk_str, &disk_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], DiskControl, DiskControlOriginal);

		DISK_FAIL_PREDICTION Disky = (DISK_FAIL_PREDICTION)FindPatternImage(disk_object->DriverStart, "\x48\x8B\x00\x24\x10\x48\x8B\x74\x24\x18\x57\x48\x83\xEC\x90", "xx?xxxxxxxxxxxx");

		if (Disky) {
			ULONG length = 0;

			if (STATUS_BUFFER_TOO_SMALL == IoEnumerateDeviceObjectList(disk_object, NULL, 0, &length) && length) {
				ULONG size = length * sizeof(PDEVICE_OBJECT);
				PDEVICE_OBJECT* devices = ExAllocatePool(NonPagedPool, size);

				if (devices) {
					if (NT_SUCCESS(IoEnumerateDeviceObjectList(disk_object, devices, size, &length)) && length) {
						LONG success = 0, total = 0;

						for (ULONG i = 0; i < length; ++i) {
							PDEVICE_OBJECT device = devices[i];

							PDEVICE_OBJECT disk = IoGetAttachedDeviceReference(device);
							if (disk) {
								UpdateDiskProperties(disk);
								ObDereferenceObjectWithTag(disk, 'tBoa');
							}

							PFUNCTIONAL_DEVICE_EXTENSION ext = (PFUNCTIONAL_DEVICE_EXTENSION)device->DeviceExtension;
							if (ext) {
								RtlCopyMemory((PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset, SERIAL, sizeof(SERIAL));

								if (NT_SUCCESS(DisableSmart(ext, Disky))) {
									InterlockedIncrement(&success);
								}

								InterlockedIncrement(&total);
							}

							ObDereferenceObjectWithTag(device, 'tToa');
						}

						ExFreePoolWithTag(devices, 'tFre');
					}
				}
			}

			ObDereferenceObjectWithTag(disk_object, 'tTot');
		}
	}
}

typedef struct _SMBIOS_TYPE1 {
	UCHAR Type;
	UCHAR Length;
	USHORT Handle;
	UCHAR Manufacturer;
	UCHAR ProductName;
	UCHAR Version;
	UCHAR SerialNumber;
	GUID UUID;
	UCHAR WakeUpType;
	UCHAR SKU;
	UCHAR Family;
} SMBIOS_TYPE1, * PSMBIOS_TYPE1;
NTSTATUS SMBIOS_SpoofInit() {
	PVOID ntoskrnl_base = GetBaseAddress("ntoskrnl.exe", 0);
	if (!ntoskrnl_base)
		return STATUS_UNSUCCESSFUL;

	PPHYSICAL_ADDRESS smbiosphysicaladdy = (PPHYSICAL_ADDRESS)FindPatternImage(ntoskrnl_base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if (smbiosphysicaladdy) {
		smbiosphysicaladdy = (PPHYSICAL_ADDRESS)((char*)smbiosphysicaladdy + 7 + *(int*)((char*)smbiosphysicaladdy + 3));
		memset(smbiosphysicaladdy, 0, sizeof(PHYSICAL_ADDRESS));
	}
	else
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}
//VOID yes() {
//	// Read the serial number from a file
//	readshitfile();
//
//	// Swap the IRP_MJ_DEVICE_CONTROL handler of the volmgr driver
//	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\volmgr"), PartControl, PartControlOriginal);
//
//	// Find the disk driver object
//	UNICODE_STRING disk_str = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
//	PDRIVER_OBJECT disk_object = 0;
//	NTSTATUS status = ObReferenceObjectByName(&disk_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &disk_object);
//	if (!NT_SUCCESS(status)) {
//		return;
//	}
//
//	// Append a new IRP_MJ_DEVICE_CONTROL handler to the disk driver object
//	AppendSwap(disk_str, &disk_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], DiskControl, DiskControlOriginal);
//
//	// Find the function to enable/disable SMART on a disk
//	DISK_FAIL_PREDICTION DiskEnableDisableFailurePrediction = (DISK_FAIL_PREDICTION)FindPatternImage(disk_object->DriverStart, "\x48\x89\x00\x24\x10\x48\x89\x74\x24\x18\x57\x48\x81\xEC\x90\x00", "xx?xxxxxxxxxxxxx");
//	if (DiskEnableDisableFailurePrediction) {
//		// Enumerate all the device objects in the disk driver stack
//		ULONG length = 0;
//		if (STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(disk_object, 0, 0, &length)) && length) {
//			ULONG size = length * sizeof(PDEVICE_OBJECT);
//			PDEVICE_OBJECT* devices = ExAllocatePool(NonPagedPool, size);
//			if (devices) {
//				if (NT_SUCCESS(status = IoEnumerateDeviceObjectList(disk_object, devices, size, &length)) && length) {
//					ULONG success = 0, total = 0;
//
//					for (ULONG i = 0; i < length; ++i) {
//						PDEVICE_OBJECT device = devices[i];
//
//						// Update disk properties for disk ID
//						PDEVICE_OBJECT disk = IoGetAttachedDeviceReference(device);
//						if (disk) {
//							KEVENT event = { 0 };
//							KeInitializeEvent(&event, NotificationEvent, FALSE);
//
//							PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_UPDATE_PROPERTIES, disk, 0, 0, 0, 0, 0, &event, 0);
//							if (irp) {
//								if (STATUS_PENDING == IoCallDriver(disk, irp)) {
//									KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
//								}
//							}
//							else {
//								// failed to allocate IRP
//							}
//
//							ZwClose(disk);
//						}
//
//						PFUNCTIONAL_DEVICE_EXTENSION ext = device->DeviceExtension;
//						if (ext) {
//							// set the disk serial number
//							strcpy((PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset, SERIAL);
//
//							// Disables SMART
//							if (NT_SUCCESS(status = DiskEnableDisableFailurePrediction(ext, FALSE))) {
//								++success;
//							}
//							else {
//								// failed to disable failure prediction
//							}
//
//							++total;
//						}
//
//						ObDereferenceObjectWithTag(device, 'tDev');
//					}
//
//					// Free the memory allocated for the devices array
//					ExFreePool(devices);
//
//					// Dereference the disk object
//					ObDereferenceObjectWithTag(disk_object, 'tDis');
//				}
//			}
//
//		}
//	}
//
//}


typedef struct _VOLUME_ID_SPOOF {
	ULONG VolumeID[4];
} VOLUME_ID_SPOOF;


typedef struct _BIOS_SERIAL_SPOOF {
	ULONG BaseboardSerial[4];
} BIOS_SERIAL_SPOOF;


VOLUME_ID_SPOOF g_VolumeIDSpoof = { 0x12345678, 0x87654321, 0x12345678, 0x87654321 };
BIOS_SERIAL_SPOOF g_BiosSerialSpoof = { 0x12345678, 0x87654321, 0x12345678, 0x87654321 };

NTSTATUS SpoofVolumeID(volatile VOLUME_ID_SPOOF* pVolumeID)
{

	pVolumeID->VolumeID[0] = g_VolumeIDSpoof.VolumeID[0];
	pVolumeID->VolumeID[1] = g_VolumeIDSpoof.VolumeID[1];
	pVolumeID->VolumeID[2] = g_VolumeIDSpoof.VolumeID[2];
	pVolumeID->VolumeID[3] = g_VolumeIDSpoof.VolumeID[3];


	return STATUS_SUCCESS;
}

// Create routine to spoof BIOS serial number 
NTSTATUS SpoofBiosSerialNumber(volatile BIOS_SERIAL_SPOOF* pBiosSerialNumber)
{

	pBiosSerialNumber->BaseboardSerial[0] = g_BiosSerialSpoof.BaseboardSerial[0];
	pBiosSerialNumber->BaseboardSerial[1] = g_BiosSerialSpoof.BaseboardSerial[1];
	pBiosSerialNumber->BaseboardSerial[2] = g_BiosSerialSpoof.BaseboardSerial[2];
	pBiosSerialNumber->BaseboardSerial[3] = g_BiosSerialSpoof.BaseboardSerial[3];


	return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT driver) {
	UNREFERENCED_PARAMETER(driver);
	printf("-- unloading\n");

	for (DWORD i = 0; i < SWAPS.Length; ++i) {
		PSWAP s = (PSWAP)&SWAPS.Buffer[i];
		if (s->Swap && s->Original) {
			InterlockedExchangePointer(s->Swap, s->Original);
			printf("reverted %wZ swap\n", &s->Name);
		}
	}

	printf("-- unloaded\n");
}
ULONG GetTickCount(VOID)
{
	LARGE_INTEGER liTime;
	KeQuerySystemTime(&liTime);
	ULONG ulTime = (ULONG)(liTime.QuadPart / 10000);

	return ulTime;
}


// @param seed		The seed to use for scrambling
// @param serial	The serial to scramble
void ScrambleSerial(DWORD seed, CHAR* serial)
{
	for (DWORD i = 0; i < seed; i++)
	{
		CHAR temp = serial[0];
		for (DWORD j = 0; j < strlen(serial) - 1; j++)
		{
			serial[j] = serial[j + 1];
		}
		serial[strlen(serial) - 1] = temp;
	}
} 

// @param serial	The serial to write the values to
// @param seed		The seed to use for generating
void GenerateFakeValues(CHAR serial[12], ULONG seed)
{
	CHAR alphabet[] = "0123456789";

	for (int i = 0; i < seed; i++)
	{
		int index = i % 12;
		int charIndex = seed % (sizeof(alphabet) - 1);

		serial[index] = alphabet[charIndex];
	}
}
void FillRandomSerial(char* serial, char* alphabet, ULONG seed)
{
	for (DWORD i = 0; i < 12; ++i) {
		if (serial[i] == '\0')
		{
			// Randomize entries that are empty
			serial[i] = alphabet[RtlRandomEx(&seed) % (sizeof(alphabet) - 1)];
		}
	}
}

//Function to encrypt the serial using an XOR cipher
void EncryptSerial(char* serial, char* encrypted_serial, ULONG seed)
{
	for (DWORD i = 0; i < 12; i++)
	{
		// Use XOR with a randomly generated 8-bit number for added encryption
		encrypted_serial[i] = serial[i] ^ (0xA5 | (RtlRandomEx(&seed) & 0xFF));
	}
}

#include <FltKernel.h>
#include <ntstatus.h>
#include <NtStrSafe.h>

void SecureEncryptSerial(CHAR serial[12], CHAR encrypted_serial[12], ULONG seed)
{
	for (int i = 0; i < 12; i++)
	{
		encrypted_serial[i] = ((serial[i] - '0') + seed) % 10 + '0';
	}
}
//// Global Variables
//ULONG SEED;
//
//
//typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
//	SYSTEM_INFORMATION_CLASS SystemInformationClass,
//	PVOID SystemInformation,
//	ULONG SystemInformationLength,
//	PULONG ReturnLength
//	);
//
//typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATIONEX)(
//	SYSTEM_INFORMATION_CLASS SystemInformationClass,
//	PVOID QueryInformation,
//	ULONG QueryInformationLength,
//	PVOID SystemInformation,
//	ULONG SystemInformationLength,
//	PULONG ReturnLength
//	);
//
//typedef struct _SYSTEM_DEVICE_INFORMATION_EX {
//	ULONG VolatileVolumes;
//	ULONG Reserved;
//
//	UCHAR BaseboardSerial[1];
//} SYSTEM_DEVICE_INFORMATION_EX, * PSYSTEM_DEVICE_INFORMATION_EX;
//
//#pragma pack(push, 1)
//typedef union _VOLUME_ID {
//	UCHAR VolumeId[16];
//	ULONGLONG VolumeIdLong;
//} VOLUME_ID, * PVOLUME_ID;
//#pragma pack(pop)
//
//
//// Hooking the ZwQuerySystemInformationEx function
//ZWQUERYSYSTEMINFORMATIONEX oldZwQuerySystemInformationEx = ZwQuerySystemInformation;
//
//NTSTATUS NTAPI NewZwQuerySystemInformationEx(
//	SYSTEM_INFORMATION_CLASS SystemInformationClass,
//	PVOID QueryInformation,
//	ULONG QueryInformationLength,
//	PVOID SystemInformation,
//	ULONG SystemInformationLength,
//	PULONG ReturnLength
//)
//{
//	NTSTATUS status = oldZwQuerySystemInformationEx(
//		SystemInformationClass,
//		QueryInformation,
//		QueryInformationLength,
//		SystemInformation,
//		SystemInformationLength,
//		ReturnLength
//	);
//
//
//	return status;
//}
//VOID RtlGenRandom(PBYTE Buffer, SIZE_T Size)
//{
//	HANDLE fileHandle;
//	IO_STATUS_BLOCK ioStatusBlock;
//	OBJECT_ATTRIBUTES objectAttributes;
//
//	UNICODE_STRING fileName;
//	RtlInitUnicodeString(&fileName, L"\\SystemRoot\\System32\\SrvApi.dll");
//
//	InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//
//	NTSTATUS status = ZwOpenFile(&fileHandle, READ_CONTROL | SYNCHRONIZE, &objectAttributes, &ioStatusBlock,
//		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
//	if (!NT_SUCCESS(status))
//		return;
//
//	FILE_STANDARD_INFORMATION info;
//	LARGE_INTEGER offset;
//	ULONG bytesRead;
//
//	offset.QuadPart = 0;
//	status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, Buffer, (ULONG)Size, &offset, NULL);
//	ZwClose(fileHandle);
//
//	if (NT_SUCCESS(status))
//		RtlSecureZeroMemory(Buffer, Size);
//}
//CHAR BtoH(BYTE x) {
//	BYTE b = x & 0x0F;
//	if (b < 10)
//		return b + '0';
//	else
//		return b + 'A' - 10;
//}
//NTSTATUS GpuControl(PDEVICE_OBJECT device, PIRP irp) {
//	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
//	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
//	case IOCTL_NVIDIA_SMIL: {
//		NTSTATUS ret = GpuControlOriginal(device, irp);
//
//		PCHAR buffer = irp->UserBuffer;
//		if (buffer) {
//			PCHAR copy = SafeCopy(buffer, IOCTL_NVIDIA_SMIL_MAX);
//			if (copy) {
//				for (DWORD i = 0; i < IOCTL_NVIDIA_SMIL_MAX - 4; ++i) {
//					if (0 == memcmp(copy + i, "GPU-", 4)) {
//						buffer[i] = 0;
//						break;
//					}
//				}
//
//				ExFreePool(copy);
//			}
//		}
//		return ret;
//	}
//	}
//	return GpuControlOriginal(device, irp);
//}
//
//VOID SpoofGPU() {
//	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nvlddmkm"), GpuControl, GpuControlOriginal);
//}

// Structure to hold a file name and command arguments
typedef struct _FILE_COMMAND
{
	PUNICODE_STRING FileName;
	PUNICODE_STRING Command;
} FILE_COMMAND, * PFILE_COMMAND;
#define CREATE_NEW_CONSOLE 0x00000010
// Function to open a file and execute a command


NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);
#include <ntddk.h>

// Function to execute a command using a file handle
/*NTSTATUS ExecuteCommand(HANDLE FileHandle, PUNICODE_STRING Command)
{
	NTSTATUS status;
	HANDLE processHandle, threadHandle;
	PROCESS_BASIC_INFORMATION processInfo;
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatus;
	PVOID commandBuffer;
	SIZE_T commandLength;
	PVOID environment;
	SIZE_T environmentLength;
	PVOID processParameters;
	SIZE_T processParametersLength;
	PVOID context;
	ULONG createFlags;
	ULONG zeroBits;

	// Allocate memory for the command buffer
	commandBuffer = ExAllocatePoolWithTag(NonPagedPool, Command->Length, 'CMD');
	if (commandBuffer == NULL)
	{
		// Failed to allocate memory
		return STATUS_NO_MEMORY;
	}

	// Copy the command string to the command buffer
	RtlCopyMemory(commandBuffer, Command->Buffer, Command->Length);

	// Set the command length
	commandLength = Command->Length;

	// Set the environment and process parameters to NULL (we are not using them in this example)
	environment = NULL;
	environmentLength = 0;
	processParameters = NULL;
	processParametersLength = 0;

	// Set the context to NULL (we are not using it in this example)
	context = NULL;

	// Set the create flags to create a new console (we want the command to be displayed in a console window)
	createFlags = CREATE_NEW_CONSOLE;

	// Set the zero bits to 0 (we are not using them in this example)
	zeroBits = 0;

	// Initialize the object attributes structure
	InitializeObjectAttributes(&objectAttributes, Command,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	// Create the process
	status = Fork(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes,
		NtCurrentProcess(), TRUE, commandBuffer, environment,
		processParameters, &ioStatus, &clientId);
	if (!NT_SUCCESS(status))
	{
		// Failed to create the process
		ExFreePoolWithTag(commandBuffer, 'CMD');
		return status;
	}

	// Get the process basic information
	status = ZwQueryInformationProcess(processHandle, ProcessBasicInformation,
		&processInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(status))
	{
		// Failed to get the process basic information
		ZwClose(processHandle);
		ExFreePoolWithTag(commandBuffer, 'CMD');
		return status;
	}

	// Initialize the object attributes structure
	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);


	// Create the thread
	status = ZwCreateThread(&threadHandle, THREAD_ALL_ACCESS, &objectAttributes,
		processHandle, &clientId, context, zeroBits, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status))
	{
		// Failed to create the thread
		ZwClose(processHandle);
		ExFreePoolWithTag(commandBuffer, 'CMD');
		return status;
	}

	// Wait for the thread to terminate
	status = ZwWaitForSingleObject(threadHandle, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		// Failed to wait for the thread to terminate
		ZwClose(threadHandle);
		ZwClose(processHandle);
		ExFreePoolWithTag(commandBuffer, 'CMD');
		return status;
	}



	// Close the handles
	ZwClose(threadHandle);
	ZwClose(processHandle);

	// Free the command buffer
	ExFreePoolWithTag(commandBuffer, 'CMD');

	// Return the exit status of the thread
	return processInfo.ExitStatus;
}

// Function to open multiple files and execute commands
NTSTATUS OpenFiles(PFILE_COMMAND Commands, ULONG Count)
{
	NTSTATUS status;
	ULONG i;

	// Loop through the list of commands
	for (i = 0; i < Count; i++)
	{
		OBJECT_ATTRIBUTES objectAttributes;
		IO_STATUS_BLOCK ioStatus;
		HANDLE fileHandle;

		// Initialize the object attributes structure
		InitializeObjectAttributes(&objectAttributes, Commands[i].FileName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		// Open the file
		status = ZwCreateFile(&fileHandle, GENERIC_READ, &objectAttributes, &ioStatus,
			NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

		// Check the return status
		if (!NT_SUCCESS(status))
		{
			// An error occurred while opening the file
			return status;
		}

		// Execute the command using the file handle
		status = ExecuteCommand(fileHandle, Commands[i].Command);

		// Check the return status
		if (!NT_SUCCESS(status))
		{
			// An error occurred while executing the command
			return status;
		}
	}

	// All files were successfully opened and commands were executed
	return STATUS_SUCCESS;
}

NTSTATUS OpenFile(PUNICODE_STRING FileName, PUNICODE_STRING Command)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatus;
	HANDLE fileHandle;

	// Initialize the object attributes structure
	InitializeObjectAttributes(&objectAttributes, FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	// Open the file
	status = ZwCreateFile(&fileHandle, GENERIC_READ, &objectAttributes, &ioStatus,
		NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	// Check the return status
	if (!NT_SUCCESS(status))
	{
		// An error occurred while opening the file
		return status;
	}

	// Execute the command using the file handle
	status = ExecuteCommand(fileHandle, Command);

	// Check the return status
	if (!NT_SUCCESS(status))
	{
		// An error occurred while executing the command
		return status;
	}

	// The file was successfully opened and the command was executed
	return STATUS_SUCCESS;
}*/
//SOON
NTSTATUS CreateSpooferFile(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING fileName;
	HANDLE fileHandle;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;
	char* buffer = "LOADED SPOOFER SUCCED";
	LARGE_INTEGER byteOffset;
	ULONG bytesWritten;

	// Create a Unicode string for the file name
	RtlInitUnicodeString(&fileName, L"\\??\\C:\\Spoofer\\log.txt");

	// Initialize the object attributes for the file
	InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// Create the file
	status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error creating file: 0x%X\n", status);
		return status;
	}

	// Write the buffer to the file
	byteOffset.QuadPart = 0;
	status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, buffer, (ULONG)strlen(buffer), &byteOffset, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error writing to file: 0x%X\n", status);
		ZwClose(fileHandle);
		return status;
	}

	bytesWritten = (ULONG)ioStatus.Information;
	DbgPrint("Wrote %d bytes to file\n", bytesWritten);

	// Close the file
	ZwClose(fileHandle);

	return STATUS_SUCCESS;
}
SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
}
BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD dwOldProtect = 0;

	if (VirtualQuery(lpAddress, &mbi, sizeof(mbi)) == 0)
		return FALSE;

	if (mbi.Protect & PAGE_GUARD) {
		dwOldProtect = PAGE_READWRITE;
	}
	else {
		dwOldProtect = mbi.Protect;
	}

	if (VirtualProtect(lpAddress, dwSize, flNewProtect, &dwOldProtect) == 0)
		return FALSE;

	if (lpflOldProtect != NULL)
		*lpflOldProtect = dwOldProtect;

	return TRUE;
}
void BIUS()
{
	// Get the base address of ntoskrnl.exe 
	PVOID base = GetBaseAddress("ntoskrnl.exe", 0);
	if (!base)
	{
		printf("! failed to get \"ntoskrnl.exe\" !\n");
		return;
	}

	// Find the ExpBootEnvironmentInformation pattern in the ntoskrnl.exe image 
	PBYTE ExpBootEnvironmentInformation = FindPatternImage(base, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");
	if (ExpBootEnvironmentInformation)
	{
		// Spoof the SMBIOS information 
		ExpBootEnvironmentInformation = ExpBootEnvironmentInformation + 7 + *(PINT)(ExpBootEnvironmentInformation + 3);
		SpoofBuffer(SEED, ExpBootEnvironmentInformation, 16);

		printf("handled ExpBootEnvironmentInformation\n");
	}
	else
	{
		printf("! ExpBootEnvironmentInformation not found !\n");
	}

	// Find the WmipSMBiosTablePhysicalAddress pattern in the ntoskrnl.exe image 
	PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if (WmipSMBiosTablePhysicalAddress)
	{
		// Zero out the SMBIOS table physical address 
		WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((PBYTE)WmipSMBiosTablePhysicalAddress + 7 + *(PINT)((PBYTE)WmipSMBiosTablePhysicalAddress + 3));
		memset(WmipSMBiosTablePhysicalAddress, 0, sizeof(PHYSICAL_ADDRESS));

		printf("nulled SMBIOS table physical address\n");
	}
	else
	{
		printf("! WmipSMBiosTablePhysicalAddress not found !\n");
		return;
	}

	// Hide the system time 
	// Find the KiUpdateTimeZoneInfo pattern in the ntoskrnl.exe image 
	PVOID KiUpdateTimeZoneInfo = FindPatternImage(base, "\x48\x8B\xC4\x48\x89\x58\x10\x48\x89\x70\x18\x48\x89\x78\x20\x48\x83\xEC\x40\x0F\x29\x7C\x24\x00", "xxxxxxxxxxxxxxxxxxxxxx?");
	if (KiUpdateTimeZoneInfo)
	{
		// Replace the KiUpdateTimeZoneInfo function with a dummy function that does nothing 
		BYTE dummy[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90 };
		*(PVOID*)&dummy[2] = KiUpdateTimeZoneInfo;
		extern int WriteMemory(void* KiUpdateTimeZoneInfo, void* dummy, int size);
		printf("replaced KiUpdateTimeZoneInfo\n");
	}
	else
	{
		printf("! KiUpdateTimeZoneInfo not found !\n");
		return;
	}
}
#define IOCTL_ENCRYPT_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _ENCRYPT_DATA_IN
{
	DWORD dataSize;
	PBYTE data;
} ENCRYPT_DATA_IN, * PENCRYPT_DATA_IN;
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _ENCRYPT_DATA_OUT
{
	DWORD encryptedDataSize;
	PBYTE encryptedData;
} ENCRYPT_DATA_OUT, * PENCRYPT_DATA_OUT;



NTSTATUS hide_driver(PDRIVER_OBJECT driver_object) {
	PLDR_DATA_TABLE_ENTRY entry;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KIRQL irql;
	irql = KeRaiseIrqlToDpcLevel();
	for (entry = (PLDR_DATA_TABLE_ENTRY)driver_object->DriverSection; entry->InLoadOrderLinks.Flink != NULL; entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink) {
		if (entry->DllBase == (PVOID)driver_object->DriverStart) {
			RemoveEntryList(&entry->InLoadOrderLinks);
			RemoveEntryList(&entry->InMemoryOrderLinks);
			RemoveEntryList(&entry->InInitializationOrderLinks);
			entry->InLoadOrderLinks.Flink = NULL;
			entry->InLoadOrderLinks.Blink = NULL;
			entry->InMemoryOrderLinks.Flink = NULL;
			entry->InMemoryOrderLinks.Blink = NULL;
			entry->InInitializationOrderLinks.Flink = NULL;
			entry->InInitializationOrderLinks.Blink = NULL;
			status = STATUS_SUCCESS;
			break;
		}
	}
	KeLowerIrql(irql);
	return status;
}

#include <wdf.h>
#define SHARED_MEM_TAG 'MHSM'
#define SHARED_MEM_SIZE 0x1000

typedef struct _SHARED_MEM {
	ULONG Data;
} SHARED_MEM, * PSHARED_MEM;

PSHARED_MEM g_SharedMem = NULL;
typedef struct _HOOK_ENTRY {
	PVOID OriginalFunction;
	PVOID HookFunction;
	PVOID TrampolineFunction;
	LIST_ENTRY ListEntry;
} HOOK_ENTRY, * PHOOK_ENTRY;

#define HOOK_SIZE 12
#define ALLOC_TAG 'HOOK'

LIST_ENTRY g_HookList;

typedef struct _JMP_REL {
	UCHAR opcode;
	CHAR offset;
} JMP_REL, * PJMP_REL;

#define JMP_REL_SHORT(x) { 0xEB, (CHAR)(x) }
// Original function
NTSTATUS OriginalFunction(PVOID Param1, PVOID Param2)
{
	// Your logic for the original function goes here

	NTSTATUS status = STATUS_SUCCESS;

	// Perform some operation
	DbgPrint("OriginalFunction: Performing operation...\n");

	// ...

	return status;
}

// Trampoline function
NTSTATUS TrampolineFunction(PVOID Param1, PVOID Param2)
{
	// Your logic for the trampoline function goes here

	DbgPrint("TrampolineFunction: Hook called...\n");

	// Call the original function
	NTSTATUS status = OriginalFunction(Param1, Param2);

	DbgPrint("TrampolineFunction: Original function returned...\n");

	return status;
}

NTSTATUS MmInstallHook(PVOID OriginalFunction, PVOID HookFunction)
{
	PHOOK_ENTRY hookEntry = NULL;
	PVOID trampolineFunction = NULL;
	PUCHAR trampoline = NULL;
	LARGE_INTEGER hookSize;
	NTSTATUS status = STATUS_SUCCESS;

	// Allocate memory for the hook entry
	hookEntry = (PHOOK_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_ENTRY), ALLOC_TAG);
	if (hookEntry == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Allocate memory for the trampoline function
	hookSize.QuadPart = HOOK_SIZE + sizeof(JMP_REL);
	trampolineFunction = ExAllocatePoolWithTag(NonPagedPoolExecute, (SIZE_T)hookSize.QuadPart, ALLOC_TAG);
	if (trampolineFunction == NULL) {
		ExFreePoolWithTag(hookEntry, ALLOC_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Copy the original function to the trampoline function
	RtlCopyMemory(trampolineFunction, OriginalFunction, HOOK_SIZE);

	// Create a relative jump from the trampoline function to the original function
	trampoline = (PUCHAR)trampolineFunction + HOOK_SIZE;
	//*(PJMP_REL)trampoline = JMP_REL_SHORT((PUCHAR)OriginalFunction + HOOK_SIZE - (trampoline + sizeof(JMP_REL)));

	// Replace the first few bytes of the original function with a relative jump to the hook function
	//*(PJMP_REL)OriginalFunction = JMP_REL_SHORT((PUCHAR)HookFunction - ((PUCHAR)OriginalFunction + sizeof(JMP_REL)));

	// Fill in the hook entry
	hookEntry->OriginalFunction = OriginalFunction;
	hookEntry->HookFunction = HookFunction;
	hookEntry->TrampolineFunction = trampolineFunction;
	InitializeListHead(&hookEntry->ListEntry);

	// Add the hook entry to the list of hooks
	InsertTailList(&g_HookList, &hookEntry->ListEntry);

	return status;
}

NTSTATUS MyHookFunction(PVOID OriginalFunction, PVOID HookFunction)
{
	// Your hook logic goes here
	ULONG functionCallCounter = 0;

	// Increment the function call counter
	functionCallCounter++;

	// Call the original function
	NTSTATUS status = ((NTSTATUS(*)(PVOID, PVOID))OriginalFunction)(OriginalFunction, HookFunction);

	// Return the result
	return status;
}
NTSTATUS CreateSharedMemory()
{
	NTSTATUS status;
	UNICODE_STRING sharedMemName;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE sharedMemHandle = NULL;

	RtlInitUnicodeString(&sharedMemName, L"\\BaseNamedObjects\\MySharedMem");
	InitializeObjectAttributes(&objectAttributes, &sharedMemName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateSection(&sharedMemHandle, SECTION_ALL_ACCESS, &objectAttributes, NULL, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	/*ULONG sharedMemSize = SHARED_MEM_SIZE;

	status = ZwMapViewOfSection(sharedMemHandle, ZwCurrentProcess(), (PVOID*)&g_SharedMem, 0, &sharedMemSize, NULL, &sharedMemSize, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		ZwClose(sharedMemHandle);
		return status;
	}*/

	ZwClose(sharedMemHandle);
	return STATUS_SUCCESS;
}
NTSTATUS HookKernelModule(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING functionName;
	PVOID originalFunctionAddress;
	PVOID hookFunctionAddress;

	// Convert the function name to a UNICODE_STRING structure
	RtlInitUnicodeString(&functionName, L"ntoskrnl.exe!MyFunction");

	// Get the address of the original function
	originalFunctionAddress = MmGetSystemRoutineAddress(&functionName);
	if (originalFunctionAddress == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	// Get the address of the hook function
	hookFunctionAddress = MyHookFunction;

	// Perform the hook
	return MmInstallHook(originalFunctionAddress, hookFunctionAddress);
}
#define ALLOC_TAG 'MyT'
#define IOCTL_SPOOF_GPU_SERIAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Function to generate a spoofed GPU serial
VOID GenerateSpoofedGpuSerial(PCHAR spoofedSerial) {
	CHAR alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234560_";
	for (DWORD i = 0; i < 12; ++i) {
		spoofedSerial[i] = alphabet[RtlRandomEx(&SEED) % (sizeof(alphabet) - 1)];
	}
	spoofedSerial[12] = '\0';
}
NTSTATUS GpuControlSpoofed(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_SPOOF_GPU_SERIAL) {
		PCHAR buffer = irp->UserBuffer;
		if (buffer) {
			CHAR spoofedGpuSerial[13];
			GenerateSpoofedGpuSerial(spoofedGpuSerial);
			RtlCopyMemory(buffer, spoofedGpuSerial, 12);
			buffer[12] = '\0';
		}
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 12;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
	return GpuControlOriginal(device, irp);
}
NTSTATUS UpdateGPUDescription(PDEVICE_OBJECT deviceObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT targetDevice;
	UNICODE_STRING description;
	WCHAR newDescription[] = L"ABCDEFGH12345";

	status = IoGetDeviceProperty(deviceObject, DevicePropertyDeviceDescription, sizeof(newDescription), newDescription, NULL);
	if (NT_SUCCESS(status))
	{
		targetDevice = IoGetAttachedDeviceReference(deviceObject);
		if (targetDevice)
		{
			RtlInitUnicodeString(&description, newDescription);
			status = ZwSetValueKey(targetDevice->DeviceObjectExtension, &description, 0, REG_SZ, newDescription, sizeof(newDescription));
			ObDereferenceObjectWithTag(targetDevice, 'tEar');
		}
	}

	return status;
}
#include <windef.h>

#define ALLOC_TAG 'GICP'

PVOID dataPtr = NULL;

NTSTATUS GpuControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_NVIDIA_SMIL: {
		NTSTATUS ret = GpuControlOriginal(device, irp);

		PCHAR buffer = irp->UserBuffer;
		if (buffer) {
			PCHAR copy = SafeCopy(buffer, IOCTL_NVIDIA_SMIL_MAX);
			if (copy) {
				for (DWORD i = 0; i < IOCTL_NVIDIA_SMIL_MAX - 4; ++i) {
					if (0 == memcmp(copy + i, "GPU-", 4)) {
						buffer[i] = 0;
						break;
					}
				}

				ExFreePool(copy);
			}
		}
		return ret;
	}
	}
	return GpuControlOriginal(device, irp);
}

void ChangeGPU() {
	PCHAR buffer = dataPtr;
	DWORD length = strlen(buffer);
	for (DWORD i = 0; i < length; ++i) {
		buffer[i] = RtlRandomEx(&SEED) % 26 + 'A';
	}
}

VOID SpoofGPU() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\igdkmd64"), GpuControl, GpuControlOriginal);
}
NTSTATUS UpdatePNPDeviceID(PDEVICE_OBJECT deviceObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT targetDevice;
	UNICODE_STRING deviceId;
	WCHAR newDeviceId[] = L"ABCDEFGH12345";

	status = IoGetDeviceProperty(deviceObject, DevicePropertyPhysicalDeviceObjectName, sizeof(newDeviceId), newDeviceId, NULL);
	if (NT_SUCCESS(status))
	{
		targetDevice = IoGetAttachedDeviceReference(deviceObject);
		if (targetDevice)
		{
			RtlInitUnicodeString(&deviceId, newDeviceId);
			status = ZwSetValueKey(targetDevice->DeviceObjectExtension, &deviceId, 0, REG_SZ, newDeviceId, sizeof(newDeviceId));
			ObDereferenceObjectWithTag(targetDevice, 'tAge');
		}
	}

	return status;
}

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

#define SPOOFED_GPU_DESCRIPTION "NVIDIA GeForce GTX 1080 Ti"
#define SPOOFED_PNP_DEVICE_ID "PCI\\VEN_10DE&DEV_1B06&SUBSYS_85E41043&REV_A1"

NTSTATUS SpoofGpu1()
{
	NTSTATUS status = STATUS_SUCCESS;
	PFILE_OBJECT pFileObject;
	PDEVICE_OBJECT pDeviceObject;
	PDEVICE_OBJECT pLowerDeviceObject;
	UNICODE_STRING szDeviceName;

	RtlInitUnicodeString(&szDeviceName, L"\\Device\\Video0");
	status = IoGetDeviceObjectPointer(&szDeviceName, FILE_READ_DATA, &pFileObject, &pDeviceObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoGetDeviceObjectPointer failed: %08X\n", status);
		return status;
	}

	pLowerDeviceObject = IoGetLowerDeviceObject(pDeviceObject);
	if (!pLowerDeviceObject)
	{
		DbgPrint("IoGetLowerDeviceObject failed\n");
		return STATUS_UNSUCCESSFUL;
	}

	PDEVICE_OBJECT pTopDeviceObject = IoGetAttachedDevice(pLowerDeviceObject);
	if (!pTopDeviceObject)
	{
		DbgPrint("IoGetAttachedDevice failed\n");
		return STATUS_UNSUCCESSFUL;
	}

	for (PDEVICE_OBJECT pCurrentDeviceObject = pTopDeviceObject; pCurrentDeviceObject != NULL; pCurrentDeviceObject = pCurrentDeviceObject->AttachedDevice)
	{
		POBJECT_NAME_INFORMATION pObjectNameInformation;
		ULONG returnLength;

		status = ObQueryNameString(pCurrentDeviceObject, NULL, 0, &returnLength);
		if (status != STATUS_INFO_LENGTH_MISMATCH)
		{
			DbgPrint("ObQueryNameString failed: %08X\n", status);
			continue;
		}

		pObjectNameInformation = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, returnLength, 'TAG');
		if (!pObjectNameInformation)
		{
			DbgPrint("ExAllocatePoolWithTag failed\n");
			continue;
		}

		status = ObQueryNameString(pCurrentDeviceObject, pObjectNameInformation, returnLength, &returnLength);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ObQueryNameString failed: %08X\n", status);
			ExFreePoolWithTag(pObjectNameInformation, 'TAG');
			continue;
		}

		if (pObjectNameInformation->Name.Length > 0)
		{
			// Check if the device object is the target GPU
			if (wcsstr(pObjectNameInformation->Name.Buffer, L"\\Device\\Video") != NULL)
			{
				PDEVICE_OBJECT pTargetDeviceObject = NULL;
				PVOID pDeviceExtension = pCurrentDeviceObject->DeviceExtension;

				if (pDeviceExtension)
				{
					// Spoof the GPU description
					RtlCopyMemory(pDeviceExtension, SPOOFED_GPU_DESCRIPTION, sizeof(SPOOFED_GPU_DESCRIPTION));

					// Spoof the PNP Device ID
					RtlCopyMemory(((PUCHAR)pDeviceExtension) + sizeof(SPOOFED_GPU_DESCRIPTION), SPOOFED_PNP_DEVICE_ID, sizeof(SPOOFED_PNP_DEVICE_ID));
				}

			}

			ExFreePoolWithTag(pObjectNameInformation, 'TAG');
		}

		ObDereferenceObject(pFileObject);

		return status;

	}
}
NTSTATUS SpoofGpuControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_NVIDIA_SMIL) {
		NTSTATUS ret = GpuControlOriginal(device, irp);
		PCHAR buffer = irp->UserBuffer;
		if (buffer) {
			PCHAR copy = SafeCopy(buffer, ioc->Parameters.DeviceIoControl.InputBufferLength);
			if (copy) {
				DWORD len = strlen(copy);
				for (DWORD i = 0; i < len - 4; ++i) {
					if (0 == memcmp(copy + i, "GPU-", 4)) {
						memset(buffer + i, 0, 4 * sizeof(char));
						break;
					}
				}
				ExFreePool(copy);
			}
		}
		return ret;
	}
	return GpuControlOriginal(device, irp);
}



NTSTATUS NICIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (irp->MdlAddress) {
			SpoofBuffer(SEED, (PBYTE)MmGetSystemAddressForMdl(irp->MdlAddress), 6);

		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NICControl(PDEVICE_OBJECT device, PIRP irp) {
	for (DWORD i = 0; i < NICs.Length; ++i) {
		PNIC_DRIVER driver = &NICs.Drivers[i];

		if (driver->Original && driver->DriverObject == device->DriverObject) {
			PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
			switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
			case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
				switch (*(PDWORD)irp->AssociatedIrp.SystemBuffer) {
				case OID_802_3_PERMANENT_ADDRESS:
				case OID_802_3_CURRENT_ADDRESS:
				case OID_802_5_PERMANENT_ADDRESS:
				case OID_802_5_CURRENT_ADDRESS:
					ChangeIoc(ioc, irp, NICIoc);
					break;
				}

				break;
			}
			}

			return driver->Original(device, irp);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NsiControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_NSI_PROXY_ARP: {
		DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
		NTSTATUS ret = NsiControlOriginal(device, irp);

		PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
		if (params && NSI_PARAMS_ARP == params->Type) {
			memset(irp->UserBuffer, 0, length);

		}

		return ret;
	}
	}

	return NsiControlOriginal(device, irp);
}
VOID SpoofRame() {
	PVOID base = GetBaseAddress("ntoskrnl.exe", 0);
	if (!base) {
		return;
	}

	PDWORD ntoskrnl_SMBIOS_PhysicalMemoryArray = FindPatternImage(base, "\x48\x8B\x05\x00\x00\x00\x00\x48\x03\xC8\x48\x8B\x00\x48\x8B\x40\x30", "xxx????xxxxxxx?xx");
	if (ntoskrnl_SMBIOS_PhysicalMemoryArray) {
		ntoskrnl_SMBIOS_PhysicalMemoryArray = (PDWORD)((PBYTE)ntoskrnl_SMBIOS_PhysicalMemoryArray + *(PDWORD)((PBYTE)ntoskrnl_SMBIOS_PhysicalMemoryArray + 3) + 7);
		PBYTE smbios = *(PBYTE*)ntoskrnl_SMBIOS_PhysicalMemoryArray;
		if (smbios) {
			PBYTE entry = smbios + *(PWORD)(smbios + 0x16);
			while (entry[0] == 0) {
				if (entry[1] == 17) {
					// Physical Memory Array
					PBYTE serials = entry + 0x10;
					for (DWORD i = 0; i < (*(PWORD)(entry + 0x06)); ++i) {
						serials[0] = 0;
						serials[1] = 0;
						serials = serials + 0x20;
					}
					break;
				}

				entry = entry + entry[0];
			}
		}
	}
}


VOID SpoofNIC() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy"), NsiControl, NsiControlOriginal);

	PVOID base = GetBaseAddress("ndis.sys", 0);
	if (!base) {
		return;
	}

	PNDIS_FILTER_BLOCK ndisGlobalFilterList = FindPatternImage(base, "\x40\x8A\xF0\x48\x8B\x05", "xxxxxx");
	if (ndisGlobalFilterList) {
		PDWORD ndisFilter_IfBlock = FindPatternImage(base, "\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33", "xx?xx?????x???xxx");
		if (ndisFilter_IfBlock) {
			DWORD ndisFilter_IfBlock_offset = *(PDWORD)((PBYTE)ndisFilter_IfBlock + 12);

			ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)((PBYTE)ndisGlobalFilterList + 3);
			ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK*)((PBYTE)ndisGlobalFilterList + 7 + *(PINT)((PBYTE)ndisGlobalFilterList + 3));

			DWORD count = 0;
			for (PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter; filter = filter->NextFilter) {
				PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK*)((PBYTE)filter + ndisFilter_IfBlock_offset);
				if (block) {
					PWCHAR copy = SafeCopy(filter->FilterInstanceName->Buffer, MAX_PATH);
					if (copy) {
						WCHAR adapter[MAX_PATH] = { 0 };
						swprintf(adapter, L"\\Device\\%ws", TrimGUID(copy, MAX_PATH / 2));
						ExFreePool(copy);


						UNICODE_STRING name = { 0 };
						RtlInitUnicodeString(&name, adapter);

						PFILE_OBJECT file = 0;
						PDEVICE_OBJECT device = 0;

						NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
						if (NT_SUCCESS(status)) {
							PDRIVER_OBJECT driver = device->DriverObject;
							if (driver) {
								BOOL exists = FALSE;
								for (DWORD i = 0; i < NICs.Length; ++i) {
									if (NICs.Drivers[i].DriverObject == driver) {
										exists = TRUE;
										break;
									}
								}

								if (exists) {
								}
								else {
									PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
									nic->DriverObject = driver;

									AppendSwap(driver->DriverName, &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl, nic->Original);

									++NICs.Length;
								}
							}

							// Indirectly dereferences device object
							ObDereferenceObjectWithTag(file, 'tBie'); \
						}
						else {
						}
					}

					// Current MAC
					PIF_PHYSICAL_ADDRESS_LH addr = &block->ifPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);
					addr = &block->PermanentPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);

					++count;
				}
			}

		}
		else {
		}
	}
	else {
	}
}
NTSTATUS MountPointsIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
			PMOUNTMGR_MOUNT_POINTS points = (PMOUNTMGR_MOUNT_POINTS)request.Buffer;
			for (DWORD i = 0; i < points->NumberOfMountPoints; ++i) {
				PMOUNTMGR_MOUNT_POINT point = &points->MountPoints[i];
				if (point->UniqueIdOffset) {
					point->UniqueIdLength = 0;
				}

				if (point->SymbolicLinkNameOffset) {
					point->SymbolicLinkNameLength = 0;
				}
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountUniqueIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {
			((PMOUNTDEV_UNIQUE_ID)request.Buffer)->UniqueIdLength = 0;
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_MOUNTMGR_QUERY_POINTS:
		ChangeIoc(ioc, irp, MountPointsIoc);
		break;
	case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
		ChangeIoc(ioc, irp, MountUniqueIoc);
		break;
	}

	return MountControlOriginal(device, irp);
}

// Volume serial is spoofed from usermode
void SpoofVolumes() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\mountmgr"), MountControl, MountControlOriginal);
}

NTSTATUS IoCreateDriver(PUNICODE_STRING, PDRIVER_INITIALIZE);
NTSYSCALLAPI PLIST_ENTRY NTAPI PsLoadedModuleList;


#define IOCTL_MEM_INFO 0x12345678
PIRP Irp;

// Main driver entry point
NTSTATUS NullifyRamSerials()
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	PVOID userBuffer = Irp->UserBuffer;

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_MEM_INFO && userBuffer)
	{
		PCHAR buffer = ExAllocatePoolWithTag(NonPagedPool, 1024, 'mSer');
		if (buffer)
		{
			RtlZeroMemory(buffer, 1024);
			__try
			{
				ProbeForWrite(userBuffer, 1024, sizeof(CHAR));
				RtlCopyMemory(userBuffer, buffer, 1024);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				ExFreePoolWithTag(buffer, 'mSer');
				Irp->IoStatus.Status = GetExceptionCode();
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return Irp->IoStatus.Status;
			}
			ExFreePoolWithTag(buffer, 'mSer');
		}
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 1024;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


#include <WmiLib.h>
#include <wmistr.h>

// Define WMI query string
#define WMI_BASEBOARD_SERIAL_QUERY L"SELECT * FROM Win32_BaseBoard"
BOOLEAN GetPhysicalMemoryRanges(PHYSICAL_MEMORY_RANGE* ranges, ULONG rangeCount, PULONG rangeCountOut) {
	ULONG i = 0;
	PVOID addr = 0;
	while (i < rangeCount && (ULONG64)addr < 0x10000000000) {
		MEMORY_BASIC_INFORMATION info;
		if (VirtualQuery(addr, &info, sizeof(info)) != sizeof(info)) {
			break;
		}
		if (info.State != MEM_COMMIT) {
			addr = (PVOID)((ULONG64)info.BaseAddress + info.RegionSize);
			continue;
		}
		ranges[i].BaseAddress.QuadPart = (ULONG64)info.BaseAddress;
		ranges[i].NumberOfBytes.QuadPart = info.RegionSize;
		addr = (PVOID)((ULONG64)info.BaseAddress + info.RegionSize);
		++i;
	}
	*rangeCountOut = i;
	return i > 0;
}

VOID SpoofRam() {
	// Get the physical memory information
	PHYSICAL_MEMORY_RANGE ranges[32];
	ULONG rangeCount;
	if (!GetPhysicalMemoryRanges(ranges, 32, &rangeCount)) {
		return;
	}

	CHAR alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234560_";
	ULONG64 time = 0;
	KeQuerySystemTime(&time);
	SEED = (DWORD)time;

	for (ULONG i = 0; i < rangeCount; ++i) {
		CHAR serial[9];
		for (ULONG j = 0; j < 8; ++j) {
			serial[j] = alphabet[RtlRandomEx(&SEED) % (sizeof(alphabet) - 1)];
		}
		serial[8] = '\0';

		// Write the new serial number to the physical memory
		PUCHAR p = MmMapIoSpace(ranges[i].BaseAddress, (SIZE_T)ranges[i].NumberOfBytes.QuadPart, MmNonCached);
		if (p) {
			memcpy(p, serial, 9);
			MmUnmapIoSpace(p, (SIZE_T)ranges[i].NumberOfBytes.QuadPart);
		}
	}
}
NTSTATUS NullifyBaseboardSerials()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID wmiBuffer = NULL;
	ULONG wmiBufferSize = 0;
	UNICODE_STRING wmiQuery;
	WNODE_ALL_DATA* wnode;

	// Initialize WMI query
	RtlInitUnicodeString(&wmiQuery, WMI_BASEBOARD_SERIAL_QUERY);

	// Execute WMI query
	status = IoWMISuggestInstanceName(NULL, &wmiQuery, 0, TRUE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// Allocate buffer
	wmiBufferSize = 1024;
	wmiBuffer = ExAllocatePoolWithTag(NonPagedPool, wmiBufferSize, 'wSer');
	if (!wmiBuffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Query WMI data block
	status = IoWMIQueryAllData(NULL, &wmiBufferSize, wmiBuffer);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(wmiBuffer, 'wSer');
		return status;
	}

	// Get the WNODE_ALL_DATA
	wnode = (WNODE_ALL_DATA*)wmiBuffer;
	PVOID baseboardSerialOffset = (PUCHAR)wnode + wnode->OffsetInstanceDataAndLength[0].OffsetInstanceData;

	// Nullify the baseboard serial number
	RtlZeroMemory(baseboardSerialOffset, wnode->OffsetInstanceDataAndLength[0].LengthInstanceData);

	// Clean up
	ExFreePoolWithTag(wmiBuffer, 'wSer');

	return STATUS_SUCCESS;
}

PLDR_DATA_TABLE_ENTRY system_module(const wchar_t* module_name)
{
	UNICODE_STRING unicode_string;
	RtlInitUnicodeString(&unicode_string, module_name);

	PLDR_DATA_TABLE_ENTRY system_module_entry = NULL;

	// Get a pointer to the PsLoadedModuleList
	PLIST_ENTRY module_list = (PLIST_ENTRY)PsLoadedModuleList;

	// Iterate through the module list and search for the specified module
	while (module_list->Flink != PsLoadedModuleList) {
		// Get the LDR_DATA_TABLE_ENTRY structure
		PLDR_DATA_TABLE_ENTRY data_table = CONTAINING_RECORD(module_list->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		// Compare the module name with the specified name
		if (RtlEqualUnicodeString(&data_table->BaseDllName, &unicode_string, TRUE)) {
			system_module_entry = data_table;
			break;
		}

		// Move to the next module in the list
		module_list = module_list->Flink;
	}

	return system_module_entry;
}

#include <ntddk.h>
#include <stdint.h>

UINT8 rand_between(UINT8 min, UINT8 max) {
	LARGE_INTEGER li;
	KeQueryTickCount(&li);

	UINT64 seed = li.QuadPart;
	seed = (seed * 6364136223846793005ULL) + 1442695040888963407ULL;

	UINT8 result = (UINT8)((seed % (max - min + 1)) + min);
	return result;
}

#define NV_MAX_DEVICES 32

UINT64 g_system;

	FORCEINLINE BOOLEAN init(void)
	{
		UINT64 nvlddmkm_base = GetBaseAddress("nvlddmkm.sys", 0);

		g_system = *(UINT64*)(nvlddmkm_base + 0xBEA9E0); // 48 8B 05 ? ? ? ? 4C 8B F2 44 8B E9

		return (g_system != 0);
	}

	FORCEINLINE UINT64 gpu_data(UINT32 gpu_instance)
	{
		UINT64 gpu_sys = *(UINT64*)(g_system + 0x1C0);
		UINT64 gpu_mgr = *(UINT64*)(gpu_sys + 0x3CAD0);

		if (!gpu_mgr)
			return 0;

		gpu_sys += 0x3C8D0;

		UINT64 gpu_device;

		while (1)
		{
			UINT32 found_instance = *(UINT32*)(gpu_sys + 0x8);

			if (found_instance == gpu_instance)
			{
				UINT64 device = *(UINT64*)gpu_sys;

				if (device != 0)
					gpu_device = device;

				break;
			}

			gpu_sys += 0x10;
		}

		return gpu_device;
	}

	FORCEINLINE UINT64 next_gpu(UINT32 device_mask, UINT32* start_index)
	{
		if (*start_index >= NV_MAX_DEVICES)
			return 0;

		for (UINT32 i = *start_index; i < NV_MAX_DEVICES; ++i)
		{
			if (device_mask & (1U << i))
			{
				*start_index = i + 1;
				return gpu_data(i);
			}
		}

		*start_index = NV_MAX_DEVICES;

		return 0;
	}

	FORCEINLINE BOOLEAN change_uuid(UINT64 gpu_object)
	{
		if (*(UINT8*)(gpu_object + 0x848))
		{
			UINT8* uuid_data = (UINT8*)(gpu_object + 0x849);

			// randomize your GPU UUID here
			uuid_data[0] = rand_between(0x01, 0xFF);
			uuid_data[1] = rand_between(0x01, 0xFF);
			uuid_data[2] = rand_between(0x01, 0xFF);
			uuid_data[3] = rand_between(0x01, 0xFF);
			uuid_data[4] = rand_between(0x01, 0xFF);
			uuid_data[5] = rand_between(0x01, 0xFF);
			uuid_data[6] = rand_between(0x01, 0xFF);
			uuid_data[7] = rand_between(0x01, 0xFF);
			uuid_data[8] = rand_between(0x01, 0xFF);
			uuid_data[9] = rand_between(0x01, 0xFF);
			uuid_data[10] = rand_between(0x01, 0xFF);
			uuid_data[11] = rand_between(0x01, 0xFF);
			uuid_data[12] = rand_between(0x01, 0xFF);
			uuid_data[13] = rand_between(0x01, 0xFF);
			uuid_data[14] = rand_between(0x01, 0xFF);
			uuid_data[15] = rand_between(0x01, 0xFF);

			return TRUE;
		}
		else
		{
			printf("device hasn't been initialized yet!");
		}

		return FALSE;
	}

	FORCEINLINE BOOLEAN spoof_gpu(void)
	{
		BOOLEAN status = FALSE;
		UINT64 gpu_sys = *(UINT64*)(g_system + 0x1C0);

		if (!gpu_sys)
			return status;

		UINT32 gpu_index,
			gpu_mask = *(UINT32*)(gpu_sys + 0x754);

		// loops through all available GPU's (limited to NV_MAX_DEVICES)
		while (1)
		{
			UINT64 gpu_object = next_gpu(gpu_mask, &gpu_index);

			if (!gpu_object)
				break;

			if (change_uuid(gpu_object))
				status = TRUE;
			else
				status = FALSE;
		}

		return status;
	}


void SpoofBaseboardSerial() {
	const auto ntoskrnl_basea = (PsLoadedModuleList + 0x30);
	auto base = system_module(L"ntoskrnl.exe");
	if (!base) {
		return;
	}
	PBYTE ExpBootEnvironmentInformation = FindPatternImage(ntoskrnl_basea, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");
	if (ExpBootEnvironmentInformation) {
		ExpBootEnvironmentInformation = ExpBootEnvironmentInformation + 7 + *(PINT)(ExpBootEnvironmentInformation + 3);
		SpoofBuffer(SEED, ExpBootEnvironmentInformation, 16);

	}
	else {
	}

	PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = FindPatternImage(ntoskrnl_basea, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if (WmipSMBiosTablePhysicalAddress) {
		WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((PBYTE)WmipSMBiosTablePhysicalAddress + 7 + *(PINT)((PBYTE)WmipSMBiosTablePhysicalAddress + 3));
		SpoofBuffer(SEED, WmipSMBiosTablePhysicalAddress, sizeof(PHYSICAL_ADDRESS));

	}
	else {
	}

}
#define LOG_FILE_PATH L"\DosDevices\C:\totoware.log"
#define ADrvPath L"\\??\\C:\\Users\\nihao\\Desktop\\test\\Test_Drv.sys"
#define ODrvPath L"\\??\\C:\\Users\\nihao\\Desktop\\test\\EasyAntiCheat.sys"
#define ServiceName  L"EasyAntiCheat"
#include "exp.hpp"

VOID SaveSerialNumberToFile() {
	// Open the log file for writing
	HANDLE hLogFile = NULL;
	UNICODE_STRING logFilePath;
	RtlInitUnicodeString(&logFilePath, LOG_FILE_PATH);
	OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), 0, &logFilePath, OBJ_CASE_INSENSITIVE, 0, 0 };
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status = ZwCreateFile(&hLogFile, GENERIC_WRITE, &oa, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (NT_SUCCESS(status) && hLogFile != NULL) {
		// Write the serial number to the log file
		ULONG bytesWritten = 0;
		CHAR logLine[256] = { 0 };
		sprintf_s(logLine, "Serial number: %s\n", SERIAL);
		ZwWriteFile(hLogFile, NULL, NULL, NULL, &ioStatus, logLine, (ULONG)strlen(logLine), NULL, NULL);

		// Close the log file
		ZwClose(hLogFile);
	}
}

#define TARGET_MZ_ADDRESS 0x30400
#define MZ_HEADER_SIZE 0x40
#define HIDE_MZ_INTERVAL_MS 1000

PKTHREAD g_hideMZThread = NULL;
BOOLEAN g_stopHideMZThread = FALSE;

VOID HideMZHeader(PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	LARGE_INTEGER interval;
	interval.QuadPart = -1 * 10000 * HIDE_MZ_INTERVAL_MS;

	while (!g_stopHideMZThread)
	{
		PVOID targetAddress = (PVOID)TARGET_MZ_ADDRESS;
		RtlZeroMemory(targetAddress, MZ_HEADER_SIZE);

		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

#include <ntifs.h>
#include <ntddk.h>
#include <mountmgr.h>
#include <stdio.h>
void SpoofSMBIOS() {
	PVOID base = GetBaseAddress("ntoskrnl.exe", 0);
	if (!base) {
		return;
	}

	PBYTE ExpBootEnvironmentInformation = FindPatternImage(base, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");
	if (ExpBootEnvironmentInformation) {
		ExpBootEnvironmentInformation = ExpBootEnvironmentInformation + 7 + *(PINT)(ExpBootEnvironmentInformation + 3);
		SpoofBuffer(SEED, ExpBootEnvironmentInformation, 16);

	}
	else {
	}

	PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if (WmipSMBiosTablePhysicalAddress) {
		WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((PBYTE)WmipSMBiosTablePhysicalAddress + 7 + *(PINT)((PBYTE)WmipSMBiosTablePhysicalAddress + 3));
		memset(WmipSMBiosTablePhysicalAddress, 0, sizeof(PHYSICAL_ADDRESS));

	}
	else {
	}

}

NTSTATUS Entrypoint(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path) 
{
	UNREFERENCED_PARAMETER(registry_path);
	UNREFERENCED_PARAMETER(driver);

	HookKernelModule(driver);
	dataPtr = ExAllocatePoolWithTag(NonPagedPool, 0x1000, ALLOC_TAG);
	if (dataPtr == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	UNICODE_STRING fileName;
	HANDLE fileHandle;
	ULONG64 time = 0;
	KeQuerySystemTime(&time);
	SEED = (DWORD)time;

	CHAR alphabet[] = "0000123456789__";
	for (DWORD i = 0; i < 20; ++i) {
		SERIAL[i] = alphabet[RtlRandomEx(&SEED) % (sizeof(alphabet) - 1)];
	}


	//CHAR serial[25];
	//CHAR disk_serial[12];
	//CHAR nic_serial[12];
	//CHAR bius_serial[12];
	//CHAR gipiu_serial[12];

	//// Securely encrypt the serial numbers
	//SecureEncryptSerial(serial, disk_serial, SERIAL);
	//SecureEncryptSerial(serial, nic_serial, SERIAL);
	//SecureEncryptSerial(serial, bius_serial, SERIAL);
	//SecureEncryptSerial(serial, gipiu_serial, SERIAL);



	DbgPrint("hi");
	if (!init())
	{
		DbgPrint("failed initializing nvidia context!"); // most likely wrong offset or no nvidia GPU/drivers installed

		
	}

	if (!spoof_gpu())
	{
		DbgPrint("failed spoofing gpu!");

		
	}

	yes();
	SaveSerialNumberToFile();
	//SpoofSMBIOS();
	//NullifyRamSerials();
//	NullifyBaseboardSerials();
//	SpoofGPU();
	SpoofNIC();
	SpoofRam();
	ChangeGPU();
	SpoofRame();
	//int numChanges = RtlRandomEx(&SERIAL) % 3 + 1;
	//for (int i = 0; i < numChanges; i++)
	//{
	//	int index = RtlRandomEx(&SERIAL) % 12;
	//	int newCharIndex = RtlRandomEx(&SERIAL) % (sizeof(alphabet) - 1);
	//	serial[index] = alphabet[newCharIndex];

	//	// Securely encrypt the serial numbers after changing characters
	//	SecureEncryptSerial(serial, disk_serial, SERIAL);
	//	SecureEncryptSerial(serial, nic_serial, SERIAL);
	//	SecureEncryptSerial(serial, bius_serial, SERIAL);
	//	SecureEncryptSerial(serial, gipiu_serial, SERIAL);
	//}

	//// Generate fake values for certain hardware components
	//GenerateFakeValues(serial, RtlRandomEx(&SERIAL) % 12);

	SpoofGpu1();

	OBJECT_ATTRIBUTES objAttribs;
	UNICODE_STRING uniFileName;
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES awert;
	UNICODE_STRING aedfb;
	IO_STATUS_BLOCK aedfbn;

	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	return IoCreateDriver(0, &Entrypoint);
}