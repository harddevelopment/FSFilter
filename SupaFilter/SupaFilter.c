#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <wdm.h>

PFLT_PORT ServerPort = NULL;
PFLT_PORT ClientPort = NULL;
PCWSTR PortName = L"\\FltAntivairusPort";

int fileFilterStatus = 1;
int registryFilterStatus = 1;

PFLT_FILTER FilterHandle;

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

WCHAR** protectedFiles = NULL;
int protectedFilesCount = 0;

WCHAR** protectedRegistry = NULL;
int protectedRegistryCount = 0;

LARGE_INTEGER g_CmCookie = { 0 };
PEX_CALLBACK_FUNCTION g_RegistryCallbackTable[MaxRegNtNotifyClass] = { 0 };

const FLT_OPERATION_REGISTRATION Callbacks[] = {
	{IRP_MJ_CREATE, 0 , MiniPreCreate, MiniPostCreate},
		{IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	Callbacks,
	MiniUnload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};



NTSTATUS FltSend(wchar_t *message) {
	NTSTATUS status;
	if (ClientPort == NULL) {
		KdPrint(("Client Port not activated git\n"));
		return 1;
	}

	WCHAR buffer[128] = { 0 };
	buffer[0] = '0';
	buffer[1] = '1';
	wcsncpy(buffer+2, message, 126);

	status = FltSendMessage(FilterHandle,
		&ClientPort,
		&buffer,
		sizeof(buffer),
		0,
		0,
		0);
	
	if (!NT_SUCCESS(status)) {
		KdPrint(("error FltSend (%x)\n", status));
	}

	return status;
}

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	FltCloseCommunicationPort(ServerPort);
	NTSTATUS status = CmUnRegisterCallback(g_CmCookie);
	FltUnregisterFilter(FilterHandle);

	for (int i = 0; i < protectedFilesCount; i++) {
		if (protectedFiles[i] != NULL)
			ExFreePool(protectedFiles[i]);
			//ExFreePoolWithTag(protectedFiles[i], 'uav3');
	}
	if (protectedFiles != NULL)
		ExFreePool(protectedFiles);
	//ExFreePoolWithTag(protectedFiles, 'uav3');


	for (int i = 0; i < protectedRegistryCount; i++) {
		if (protectedRegistry[i] != NULL)
			ExFreePool(protectedRegistry[i]);
		//ExFreePoolWithTag(protectedRegistry[i], 'uav3');
	}
	if (protectedRegistry != NULL)
		ExFreePool(protectedRegistry);
	//ExFreePoolWithTag(protectedRegistry, 'uav3');


	KdPrint(("Driver unloaded \r\n"));
	return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION fltName;
	POBJECT_NAME_INFORMATION pObjectNameInfo = NULL;

	if (protectedFilesCount == 0)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (FltObjects->FileObject->DeleteAccess == TRUE || FltObjects->FileObject->WriteAccess == TRUE) {
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
		if (NT_SUCCESS(status))
		{
			status = IoQueryFileDosDeviceName(FltObjects->FileObject, &pObjectNameInfo);
			if (NT_SUCCESS(status) && fileFilterStatus == 1)
			{
				//  KdPrint(("%ws\n", pObjectNameInfo->Name.Buffer));
				for (int i = 0; i < protectedFilesCount; i++) {
					int size = wcslen(pObjectNameInfo->Name.Buffer);
					if (size != wcslen(protectedFiles[i]))
						continue;
					int key = 0;
					KdPrint(("%ws\n", protectedFiles[i]));
					for (int j = 0; j < size; j++) {
						if (pObjectNameInfo->Name.Buffer[j] != protectedFiles[i][j]) {
							key = 1;
							break;
						}
					}
					if (key == 0) {
						KdPrint(("I FIND U!\n"));
						KdPrint(("%ws\r\n", pObjectNameInfo->Name.Buffer));
						FltSend(pObjectNameInfo->Name.Buffer);
						Data->IoStatus.Information = 0;
						Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					}
				}
				ExFreePool(pObjectNameInfo);
			}
			FltReleaseFileNameInformation(fltName);
		}
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

NTSTATUS RfRegistryCallback(__in PVOID CallbackContext, __in PVOID Argument1, __in PVOID Argument2)
{
	REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	//  If we have no operation callback routine for this operation then just return to Cm
	if (!g_RegistryCallbackTable[Operation])
		return STATUS_SUCCESS;

	//  Call our operation callback routine
	return g_RegistryCallbackTable[Operation](CallbackContext, Argument1, Argument2);
}

NTSTATUS Rfff(__in PVOID CallbackContext, __in PVOID Argument1, __in PREG_SET_VALUE_KEY_INFORMATION CallbackData)
{
	NTSTATUS status;
	PUNICODE_STRING pLocalCompleteName = NULL;
	PCUNICODE_STRING pRootObjectName;

	if (protectedRegistryCount == 0)
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectID(&g_CmCookie, CallbackData->Object, NULL, &pRootObjectName);
	if (NT_SUCCESS(status))
	{
		//  Build the new name
		USHORT cbBuffer = pRootObjectName->Length;
		cbBuffer += sizeof(wchar_t);
		cbBuffer += CallbackData->ValueName->Length;
		ULONG cbUString = sizeof(UNICODE_STRING) + cbBuffer;

		pLocalCompleteName = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, cbUString, 'tlFR');
		if (pLocalCompleteName && registryFilterStatus == 1)
		{
			pLocalCompleteName->Length = 0;
			pLocalCompleteName->MaximumLength = cbBuffer;
			pLocalCompleteName->Buffer = (PWCH)((PCCH)pLocalCompleteName + sizeof(UNICODE_STRING));

			RtlCopyUnicodeString(pLocalCompleteName, pRootObjectName);
			RtlAppendUnicodeToString(pLocalCompleteName, L"\\");
			RtlAppendUnicodeStringToString(pLocalCompleteName, CallbackData->ValueName);
			
			for (int i = 0; i < protectedRegistryCount; i++) {
				if (wcslen(protectedRegistry[i]) != cbBuffer/2) {
					continue;
				}
				if (wcsstr(pLocalCompleteName->Buffer, protectedRegistry[i]) != 0) {
					KdPrint(("%wZ\n", pLocalCompleteName));
					KdPrint(("I FIND U!\n"));
					FltSend(pLocalCompleteName->Buffer);
					ExFreePool(pLocalCompleteName);
					return STATUS_ACCESS_DENIED;
				}
			}
		}
	}

	if (pLocalCompleteName) {
		ExFreePool(pLocalCompleteName);
	}

	return STATUS_SUCCESS;
}


WCHAR* read(WCHAR* path, WCHAR* key) {
	NTSTATUS status;
	LPWSTR DataString = NULL;

	HANDLE handleRegKey = NULL;
	UNICODE_STRING RegistryKeyName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	RtlInitUnicodeString(&RegistryKeyName, path);
	InitializeObjectAttributes(&ObjectAttributes, &RegistryKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&handleRegKey, KEY_READ, &ObjectAttributes);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Not opened\r\n"));
		if (handleRegKey != NULL) {
			ZwClose(handleRegKey);
		}
		return NULL;
	}
	
	PKEY_VALUE_FULL_INFORMATION pKeyInfo = NULL;
	UNICODE_STRING ValueName;
	ULONG ulKeyInfoSize = 0;
	ULONG ulKeyInfoSizeNeeded = 0;
	RtlInitUnicodeString(&ValueName, key);
	status = ZwQueryValueKey(handleRegKey, &ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &ulKeyInfoSizeNeeded);

	if ((status == STATUS_BUFFER_TOO_SMALL) || (status == STATUS_BUFFER_OVERFLOW)) {
		ulKeyInfoSize = ulKeyInfoSizeNeeded;
		pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, 'uav1');
		if (NULL == pKeyInfo) {
			if (handleRegKey != NULL) {
				ZwClose(handleRegKey);
			}
			return NULL;
		}
		RtlZeroMemory(pKeyInfo, ulKeyInfoSize);
		status = ZwQueryValueKey(handleRegKey, &ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &ulKeyInfoSizeNeeded);
		if ((status != STATUS_SUCCESS) || (ulKeyInfoSizeNeeded != ulKeyInfoSize) || (NULL == pKeyInfo)) {
			if (handleRegKey != NULL) {
				ZwClose(handleRegKey);
			}
			if (pKeyInfo != NULL) {
				ExFreePoolWithTag(pKeyInfo, 'uav1');
			}
			return NULL;
		}

		ULONG Value_len = pKeyInfo->DataLength;
		ULONG_PTR pSrc;
		pSrc = (ULONG_PTR)((char*)pKeyInfo + pKeyInfo->DataOffset);
		DataString = (LPWSTR)ExAllocatePoolWithTag(NonPagedPool, Value_len, 'uav2');
		if (NULL == DataString) {
			if (handleRegKey != NULL) {
				ZwClose(handleRegKey);
			}
			if (pKeyInfo != NULL) {
				ExFreePoolWithTag(pKeyInfo, 'uav1');
			}
			Value_len = 0;
			return NULL;
		}
		RtlCopyMemory(DataString, (PVOID)pSrc, Value_len);
		KdPrint(("GROUP: %ws\r\n", DataString));
		//ExFreePoolWithTag(DataString, 'uav2');
	}
	
	if (handleRegKey != NULL) {
		ZwClose(handleRegKey);
	}
	if (pKeyInfo != NULL) {
		ExFreePoolWithTag(pKeyInfo, 'uav1');
	}

	return DataString;
}

WCHAR** testRead(WCHAR *value_name, WCHAR *path)
{
	//https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-a-handle-to-a-registry-key-object 
	//https://community.osr.com/discussion/98423/how-to-convert-the-value-returned-by-zwqueryvaluekey-to-string 
	HANDLE handleRegKey = NULL;
	NTSTATUS status;
	WCHAR** res = NULL;
	LPWSTR DataString = NULL;
	UNICODE_STRING RegistryKeyName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	RtlInitUnicodeString(&RegistryKeyName, path);
	InitializeObjectAttributes(&ObjectAttributes,
		&RegistryKeyName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	status = ZwOpenKey(&handleRegKey, KEY_READ, &ObjectAttributes);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Not opened\r\n"));
		if (handleRegKey != NULL)
		{
			ZwClose(handleRegKey);
		}
		return NULL;
	}
	KdPrint(("Opened\r\n"));
	PKEY_VALUE_PARTIAL_INFORMATION pKeyInfo = NULL;
	UNICODE_STRING ValueName;
	ULONG ulKeyInfoSize = 0;
	ULONG ulKeyInfoSizeNeeded = 0;

	RtlInitUnicodeString(&ValueName, value_name);

	status = ZwQueryValueKey(handleRegKey,
		&ValueName,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulKeyInfoSizeNeeded);

	KdPrint(("ZwQueryValueKey\r\n"));
	if ((status == STATUS_BUFFER_TOO_SMALL) || (status == STATUS_BUFFER_OVERFLOW) && ulKeyInfoSizeNeeded != 0)
	{
		pKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(NonPagedPool, ulKeyInfoSizeNeeded);
		KdPrint(("ExAllocatePoolWithTag\r\n"));
		if (NULL == pKeyInfo)
		{
			if (handleRegKey != NULL)
			{
				ZwClose(handleRegKey);
			}
			return NULL;
		}
		status = ZwQueryValueKey(handleRegKey,
			&ValueName,
			KeyValuePartialInformation,
			pKeyInfo,
			ulKeyInfoSizeNeeded,
			&ulKeyInfoSizeNeeded);
		if ((status != STATUS_SUCCESS) || (NULL == pKeyInfo))
		{
			if (handleRegKey != NULL)
			{
				ZwClose(handleRegKey);

			}
			if (pKeyInfo != NULL)
			{
				ExFreePool(pKeyInfo);
			}
			return NULL;
		}
		KdPrint(("AA %ws\r\n", (WCHAR*)pKeyInfo->Data));

		DataString = (WCHAR*)ExAllocatePool(NonPagedPool, pKeyInfo->DataLength + 1 * sizeof(WCHAR));
		wcscpy(DataString, (WCHAR*)pKeyInfo->Data);
		WCHAR* main = (WCHAR*)DataString;
		int current = 0;
		int num = 0, len = 0;
		while (main[current] != L'\0')
		{
			if (main[current] == '|')
			{
				num++;
			}
			current++;
		}
		num++;
		res = (WCHAR**)ExAllocatePool(NonPagedPool, sizeof(WCHAR*)*(num + 1));
		if (res == NULL)
		{
			ExFreePool(DataString);
			return NULL;
		}
		res[num] = NULL;
		num = 0;
		current = 0;
		WCHAR* unter_pointer = main;
		while (main[current] != '\0')
		{
			int save = current;
			while (main[current] != '|' && main[current] != '\0')
			{
				num++;
				current++;
			}
			if (main[current] == '|' || main[current] == '\0')
			{
				if (main[current] != '\0')
				{
					main[current] = '\0';
					current++;
				}
				num++;
				res[len] = (WCHAR*)ExAllocatePool(NonPagedPool, sizeof(WCHAR)*(num + 2));
				wcscpy(res[len], unter_pointer);
				KdPrint(("%ws\r\n", res[len]));
				len++;
				unter_pointer = unter_pointer + num;
				num = 0;
			}
		}
		KdPrint(("DONE\r\n"));
		ExFreePool(DataString);
		//https://github.com/microsoft/Windows-driver-samples/blob/master/filesys/miniFilter/NameChanger/ncinit.c
	}

	if (handleRegKey != NULL)
	{
		ZwClose(handleRegKey);
		KdPrint(("Closed handle\r\n"));
	}
	if (pKeyInfo != NULL)
	{
		ExFreePool(pKeyInfo);
		KdPrint(("Free main\r\n"));
	}
	return res;
}


void registerProtectedFiles() {
	//WCHAR* files = read(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SupaFilter", L"ProtectedFiles");
	//WCHAR* files = testRead(L"ProtectedFiles", L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SupaFilter");
	protectedFiles = testRead(L"ProtectedFiles", L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SupaFilter");


	for (int i = 0;; i++) {
		if (protectedFiles[i] == NULL)
			break;
		protectedFilesCount = i;
		KdPrint(("%ws\n", protectedFiles[i]));
	}

	KdPrint(("%d\n", protectedFilesCount));

	//while (protectedFiles[])
	//
	//KdPrint(("%ws\n", files));
	//
	//int size = wcslen(files);

	//if (files == NULL || size == 0) {
	//	return;
	//}
	//KdPrint(("%d\n", size));

	//for (int i = 0; i < size; i++) {
	//	if (files[i] == '|') {
	//		protectedFilesCount++;
	//	}
	//}
	/*if (protectedFilesCount != -1)
		protectedFilesCount++;

	KdPrint(("%d\n", protectedFilesCount));*/

	//protectedFiles = (WCHAR**)ExAllocatePoolWithTag(NonPagedPool, sizeof(WCHAR*) * protectedFilesCount, 'uav3');
	//if (protectedFiles == NULL)
	//	return;

	//for (int i = 0, ind = 0; i < size && files[i] != '\0';) {
	//	WCHAR* file = files + i;
	//	while (1) {
	//		if (files[i] == '|' || files[i] == '\0' || i == size) {
	//			files[i] = '\0';
	//			i++;
	//		//	protectedFiles[ind] = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, wcslen(file)*sizeof(WCHAR), 'uav3');
	//			KdPrint(("%ws\n", file));
	//			KdPrint(("%d\n", wcslen(file)));
	//			KdPrint(("%d\n", sizeof(file)));

	//			//for (int j = 0; j < wcslen(file) * 2; j++)
	//			//	protectedFiles[ind][j] = '\0';
	//			//if (protectedFiles[ind] == NULL) {
	//			//	KdPrint(("error..\n"));
	//			//	KdPrint(("%x\n", protectedFiles[ind]));
	//			//}
	//			//else {
	//			//	wcscpy(protectedFiles[ind], file);
	//			//	protectedFiles[ind][wcslen(file)] = '\0';
	//			//}
	//			//ind += 1;
	//			break;
	//		}
	//		i++;
	//	}
	//}
	
	//ExFreePool(files);

	//ExFreePoolWithTag(files, 'uav2');
}

void registerProtectedRegistry() {
	protectedRegistry = testRead(L"ProtectedRegistry", L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SupaFilter");

	for (int i = 0;; i++) {
		if (protectedRegistry[i] == NULL)
			break;
		protectedRegistryCount = i;
		KdPrint(("%ws\n", protectedRegistry[i]));
	}

	KdPrint(("%d\n", protectedRegistryCount));
	//WCHAR* files = read(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SupaFilter", L"ProtectedRegistry");
	//KdPrint(("%ws\n", files));
	//KdPrint(("%d\n", wcslen(files)));
	//
	//if (files == NULL || wcslen(files) == 0) {
	//	return;
	//}

	//int size = wcslen(files);
	//for (int i = 0; i < size; i++) {
	//	if (files[i] == '|') {
	//		protectedRegistryCount++;
	//	}
	//}
	//if (protectedRegistryCount != -1)
	//	protectedRegistryCount++;
	//
	//protectedRegistry = (WCHAR**)ExAllocatePoolWithTag(NonPagedPool, sizeof(WCHAR*) * protectedRegistryCount, 'uav3');
	//if (protectedRegistry == NULL)
	//	return;

	//for (int i = 0, ind = 0; i < size && files[i] != '\0';) {
	//	WCHAR* file = files + i;
	//	while (1) {
	//		if (files[i] == '|' || files[i] == '\0' || i == size) {
	//			files[i] = '\0';
	//			i++;
	//			//KdPrint(("%d\n", wcslen(file)));
	//			protectedRegistry[ind] = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, wcslen(file) * sizeof(WCHAR), 'uav3');
	//			for (int j = 0; j < wcslen(file) * 2; j++)
	//				protectedRegistry[ind][j] = '\0';
	//			if (protectedRegistry[ind] == NULL) {
	//				KdPrint(("error..\n"));
	//				KdPrint(("%x\n", protectedRegistry[ind]));
	//			}
	//			else {
	//				wcscpy(protectedRegistry[ind], file);
	//				protectedRegistry[ind][wcslen(file)] = '\0';
	//			}
	//			ind += 1;
	//			KdPrint(("%ws\n", file));
	//			break;
	//		}
	//		i++;
	//	}
	//}

	//ExFreePoolWithTag(files, 'uav2');
}

NTSTATUS
AvConnectNotifyCallback(
	_In_ PFLT_PORT _ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
	ClientPort = _ClientPort;
	KdPrint(("%x\n", ClientPort));
	KdPrint(("AvConnectNotifyCallback"));
	
	return STATUS_SUCCESS;
}

VOID
AvDisconnectNotifyCallback(
	_In_opt_ PVOID ConnectionCookie
)
{
	KdPrint(("AvDisconnectNotifyCallback"));
}

NTSTATUS
AvMessageNotifyCallback(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength
)
{
	char *msg = (char*)InputBuffer;
	KdPrint(("AvMessageNotifyCallback %s\n", msg));

	if (!strcmp(msg, "update")) {
		for (int i = 0; i < protectedFilesCount; i++) {
			if (protectedFiles[i] != NULL)
				ExFreePool(protectedFiles[i]);
		}
		if (protectedFiles != NULL)
			ExFreePool(protectedFiles);

		for (int i = 0; i < protectedRegistryCount; i++) {
			if (protectedRegistry[i] != NULL)
				ExFreePool(protectedRegistry[i]);
		}
		if (protectedRegistry != NULL)
			ExFreePool(protectedRegistry);

		registerProtectedRegistry();
		registerProtectedFiles();
	}
	else if (!strncmp(msg, "file",4)) {
		fileFilterStatus = msg[4] - 48;
		KdPrint(("fileFilterStatus= %d\n", fileFilterStatus));
	}
	else if (!strncmp(msg, "registry",8)) {
		registryFilterStatus = msg[8] - 48;
		KdPrint(("registryFilterStatus= %d\n", registryFilterStatus));
	}
	else {
		KdPrint(("get bad msg\n"));
	}
	return STATUS_SUCCESS;
}

NTSTATUS FltCreatePort() {
	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	PSECURITY_DESCRIPTOR sd;
	UNICODE_STRING uniString;

	RtlInitUnicodeString(&uniString, PortName);
	
	FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	InitializeObjectAttributes(&oa,
		&uniString,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		sd);


	status = FltCreateCommunicationPort(FilterHandle,
		&ServerPort,
		&oa,
		NULL,
		AvConnectNotifyCallback,
		AvDisconnectNotifyCallback,
		AvMessageNotifyCallback,
		1);

	KdPrint(("FltCreatePort = %d\n", status));
	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
	if (NT_SUCCESS(status))
	{
		KdPrint(("Registered \r\n"));
		status = FltStartFiltering(FilterHandle);
		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter(FilterHandle);
		}
	}
	else
	{
		KdPrint(("Registration error: %X\r\n", status));
	}

	g_RegistryCallbackTable[RegNtSetValueKey] = Rfff;
	g_RegistryCallbackTable[RegNtPreSetValueKey] = Rfff;

	UNICODE_STRING AltitudeString = RTL_CONSTANT_STRING(L"360000");
	status = CmRegisterCallbackEx(RfRegistryCallback, &AltitudeString, DriverObject, NULL, &g_CmCookie, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Registration error (driver): %X\r\n", status));
		FltUnregisterFilter(FilterHandle);
		return status;
	}

	registerProtectedFiles();
	registerProtectedRegistry();

	FltCreatePort();

	return status;
}
