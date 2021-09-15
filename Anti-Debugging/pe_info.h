#pragma once

namespace os
{
	namespace processes
	{
		namespace enumeration
		{
			bool list(std::wstring arg_process_name)
			{
				PROCESSENTRY32 process_entry;
				process_entry.dwSize = sizeof(PROCESSENTRY32);
				HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
				std::wstring process_name;

				if (Process32First(snapshot, &process_entry))
				{
					while (Process32Next(snapshot, &process_entry))
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
		namespace debug_port
		{
			bool check()
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
		}

		namespace debug_inherit
		{
			bool check()
			{
				HMODULE ntdll_handle = LoadLibraryA("ntdll.dll");

				const int process_debug_flags = 0x1f;

				auto NtQueryInfoProcess = (pNtQueryInformationProcess)(GetProcAddress(ntdll_handle, "NtQueryInformationProcess"));

				NTSTATUS status;
				DWORD no_debug_inherit = 0;

				status = NtQueryInfoProcess(GetCurrentProcess(), process_debug_flags, &no_debug_inherit, sizeof(DWORD), NULL);
				if (status == 0x00000000 && no_debug_inherit == 0)
					return true;
				else
					return false;
			}
		}

		namespace debug_object
		{
			bool check()
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

				if (status != (NTSTATUS)0xC0000353L)
					return true;

				if (handle_debug_object != NULL)
					return true;

				status = NtQueryInfoProcess(GetCurrentProcess(), process_debug_object_handle, &handle_debug_object, process_information_length, (PULONG)&handle_debug_object);
				if (status != (NTSTATUS)0xC0000353L)
					return true;

				if (handle_debug_object == NULL)
					return true;

				if ((ULONG)(ULONG_PTR)handle_debug_object != process_information_length)
					return true;

				return false;
			}
		}
	}

	namespace threads
	{
		namespace info_class
		{
			bool check()
			{
				HMODULE ntdll_handle = LoadLibraryA("ntdll.dll");

				const int thread_hide_from_debugger = 0x11;

				auto NtSetInformationThread = (pNtSetInformationThread)(GetProcAddress(ntdll_handle, "NtSetInformationThread"));
				auto NtQueryInformationThread = (pNtQueryInformationThread)(GetProcAddress(ntdll_handle, "NtQueryInformationThread"));

				NTSTATUS status;
				bool os_check = IsWindowsVistaOrGreater();
				bool is_thread_hidden = false;

				status = NtSetInformationThread(GetCurrentThread(), thread_hide_from_debugger, &is_thread_hidden, 12345);
				if (status == 0)
				{
					return true;
				}

				status = NtSetInformationThread((HANDLE)0xFFFF, thread_hide_from_debugger, NULL, 0);
				if (status == 0)
				{
					return true;
				}

				status = NtSetInformationThread(GetCurrentThread(), thread_hide_from_debugger, NULL, 0);
				if (status == 0)
				{
					if (os_check)
					{
						status = NtQueryInformationThread(GetCurrentThread(), thread_hide_from_debugger, &is_thread_hidden, sizeof(BOOL), NULL);
						if (status == 0)
						{
							return is_thread_hidden ? false : true;
						}
					}
				}
				else
				{
					return true;
				}

				return false;
			}
		}
	}
}