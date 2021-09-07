#pragma once

#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)

namespace enumeration
{
	bool debuger_present()
	{
		return IsDebuggerPresent();
	}

	bool remote_debuger_present()
	{
		BOOL result = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
		if (result == TRUE)
			return true;
		else
			return false;
	}

	bool ntglobal_flag()
	{
		PDWORD nt_global_flag = NULL, nt_global_flag_wow64 = NULL;

#if defined (x64)
		nt_global_flag = (PDWORD)(__readgsqword(0x60) + 0xBC);

#elif defined(x86)
		BYTE* _teb32 = (BYTE*)__readfsdword(0x18);
		DWORD _peb32 = *(DWORD*)(_teb32 + 0x30);
		nt_global_flag = (PDWORD)(_peb32 + 0x68);

		BYTE* _teb64 = (BYTE*)__readfsdword(0x18) - 0x2000;
		DWORD64 _peb64 = *(DWORD64*)(_teb64 + 0x60);
		nt_global_flag_wow64 = (PDWORD)(_peb64 + 0xBC);

#endif

		BOOL normal_detected = nt_global_flag && *nt_global_flag & 0x00000070;
		BOOL wow64_detected = nt_global_flag_wow64 && *nt_global_flag_wow64 & 0x00000070;

		if (normal_detected || wow64_detected)
			return true;
		else
			return false;
	}

	bool being_debug_flag()
	{
#if defined (x64)
		PPEB process_environment_block = (PPEB)__readgsqword(0x60);
#elif defined(x86)
		PPEB process_environment_block = (PPEB)__readfsdword(0x30);
#endif
		if (process_environment_block->BeingDebugged == 1)
			return true;
		else
			return false;
	}

#if defined (x64)
	PUINT32 get_heap_flags_x64()
	{
		PINT64 process_heap = NULL;
		PUINT32 heap_flags = NULL;
		if (IsWindowsVistaOrGreater()) {
			process_heap = (PINT64)(__readgsqword(0x60) + 0x30);
			heap_flags = (PUINT32)(*process_heap + 0x70);
		}

		else {
			process_heap = (PINT64)(__readgsqword(0x60) + 0x30);
			heap_flags = (PUINT32)(*process_heap + 0x14);
		}

		return heap_flags;
	}

#elif defined(x86)
	PUINT32 get_heap_flags_x86()
	{
		PUINT32 process_heap, heap_flags = NULL;
		if (IsWindowsVistaOrGreater()) {
			process_heap = (PUINT32)(__readfsdword(0x30) + 0x18);
			heap_flags = (PUINT32)(*process_heap + 0x40);
		}
		else {
			process_heap = (PUINT32)(__readfsdword(0x30) + 0x18);
			heap_flags = (PUINT32)(*process_heap + 0x0C);
		}
		return heap_flags;
	}
#endif


	bool heap_flags()
	{
		PUINT32 heap_flags = NULL;

#if defined (x64)
		heap_flags = get_heap_flags_x64();
#elif defined(x86)
		heap_flags = get_heap_flags_x86();
#endif

		if (*heap_flags > 2)
			return true;
		else
			return false;
	}


#if defined (x64)
	PUINT32 get_force_flags_x64()
	{
		PINT64 process_heap = NULL;
		PUINT32 heap_force_flags = NULL;
		if (IsWindowsVistaOrGreater()) {
			process_heap = (PINT64)(__readgsqword(0x60) + 0x30);
			heap_force_flags = (PUINT32)(*process_heap + 0x74);
		}

		else {
			process_heap = (PINT64)(__readgsqword(0x60) + 0x30);
			heap_force_flags = (PUINT32)(*process_heap + 0x18);
		}

		return heap_force_flags;
	}

#elif defined(x86)
	PUINT32 get_force_flags_x86()
	{
		PUINT32 process_heap, heap_force_flags = NULL;
		if (IsWindowsVistaOrGreater())
		{
			process_heap = (PUINT32)(__readfsdword(0x30) + 0x18);
			heap_force_flags = (PUINT32)(*process_heap + 0x44);

		}

		else {
			process_heap = (PUINT32)(__readfsdword(0x30) + 0x18);
			heap_force_flags = (PUINT32)(*process_heap + 0x10);
		}

		return heap_force_flags;
	}
#endif

	bool heap_force_flags()
	{
		PUINT32 heap_force_flags = NULL;

#if defined (x64)
		heap_force_flags = get_force_flags_x64();
#elif defined(x86)
		heap_force_flags = get_force_flags_x86();
#endif
		if (*heap_force_flags > 0)
			return true;
		else
			return false;
	}

	bool process_debugport()
	{
		HMODULE ntdll_handle = LoadLibraryA("ntdll.dll");

		if (ntdll_handle == NULL) 
			return NULL;


		auto NtQueryInfoProcess = (pNtQueryInformationProcess)(GetProcAddress(ntdll_handle, "NtQueryInformationProcess"));

		// ProcessDebugPort
		const int process_dbg_port = 7;

		// Other Vars
		NTSTATUS status;

#if defined (x64)
		DWORD process_information_length = sizeof(ULONG) * 2;
		DWORD64 is_remote_present = 0;

#elif defined(x86)
		DWORD process_information_length = sizeof(ULONG);
		DWORD32 is_remote_present = 0;
#endif

		status = NtQueryInfoProcess(GetCurrentProcess(), process_dbg_port, &is_remote_present, process_information_length, NULL);
		if (status == 0x00000000 && is_remote_present != 0)
			return true;
		else
			return false;
	}

	BOOL debug_inherit_flag()
	{
		HMODULE ntdll_handle = LoadLibraryA("ntdll.dll");

		const int process_debug_flags = 0x1f;

		auto NtQueryInfoProcess = (pNtQueryInformationProcess)(GetProcAddress(ntdll_handle, "NtQueryInformationProcess"));

		NTSTATUS status;
		DWORD no_debug_inherit = 0;

		status = NtQueryInfoProcess(GetCurrentProcess(), process_debug_flags, &no_debug_inherit, sizeof(DWORD), NULL);
		if (status == 0x00000000 && no_debug_inherit == 0)
			return TRUE;
		else
			return FALSE;
	}

	bool process_debug_object()
	{
		HMODULE ntdll_handle = LoadLibraryA("ntdll.dll");
		const int process_debug_object_handle = 0x1e;
		auto NtQueryInfoProcess = (pNtQueryInformationProcess)(GetProcAddress(ntdll_handle, "NtQueryInformationProcess"));

		NTSTATUS status;
		HANDLE handle_debug_object = NULL;

#if defined (x64)
		DWORD process_information_length = sizeof(ULONG) * 2;
		DWORD64 is_remote_present = 0;
#elif defined(x86)
		DWORD process_information_length = sizeof(ULONG);
		DWORD32 is_remote_present = 0;
#endif

		status = NtQueryInfoProcess(GetCurrentProcess(), process_debug_object_handle, &handle_debug_object, process_information_length, NULL);

		if (status != STATUS_PORT_NOT_SET)
			return true;
		
		if (handle_debug_object != NULL)
			return true;

		status = NtQueryInfoProcess(GetCurrentProcess(), process_debug_object_handle, &handle_debug_object, process_information_length, (PULONG)&handle_debug_object);
		if (status != STATUS_PORT_NOT_SET)
			return true;
		
		if (handle_debug_object == NULL)
			return true;
		
		if ((ULONG)(ULONG_PTR)handle_debug_object != process_information_length)
			return true;

		return false;
	}

	bool processes(std::wstring arg_process_name)
	{
		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(PROCESSENTRY32);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		std::wstring process_name;
		
		if (Process32First(snapshot, &process_entry) == TRUE)
		{
			while (Process32Next(snapshot, &process_entry) == TRUE)
			{
				process_name = process_entry.szExeFile;
				if (process_name == arg_process_name)
					return true;
			}
			return false;
		}
		CloseHandle(snapshot);
	}
}