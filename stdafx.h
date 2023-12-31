#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ata.h>
#include <scsi.h>
#include <ntddndis.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <classpnp.h>
#include <ntimage.h>

#include "util.h"

static DWORD SEED = 0;
static CHAR SERIAL[] = "0000000000000";

typedef struct _NIC_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
} NIC_DRIVER, * PNIC_DRIVER;

typedef struct _SWAP {
	UNICODE_STRING Name;
	PVOID* Swap;
	PVOID Original;
} SWAP, * PSWAP;

static struct {
	SWAP Buffer[0xFF];
	ULONG Length;
} SWAPS = { 0 };

// Appends swap to swap list
#define AppendSwap(name, swap, hook, original) { \
	UNICODE_STRING _n = name; \
	PSWAP _s = &SWAPS.Buffer[SWAPS.Length++]; \
	*(PVOID*)&original = _s->Original = InterlockedExchangePointer((PVOID*)(_s->Swap = (PVOID*)swap), (PVOID)hook); \
	_s->Name = _n; \
	name.Buffer = NULL; \
	name.Length = name.MaximumLength = 0; \
	printf("Swapped: %wZ\n", &_n); \
}

#define SwapControl(driver, hook, original) { \
	UNICODE_STRING str = driver; \
	PDRIVER_OBJECT object = NULL; \
	NTSTATUS _status = ObReferenceObjectByName(&str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &object); \
	if (NT_SUCCESS(_status)) { \
		AppendSwap(str, &object->MajorFunction[IRP_MJ_DEVICE_CONTROL], hook, original); \
		ObDereferenceObjectWithTag(object, 'tDis'); \
	} else { \
		printf("! Failed to get %wZ: %p !\n", &str, _status); \
	} \
}
