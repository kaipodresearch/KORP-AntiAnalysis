#pragma once

namespace pe
{
	namespace flags
	{
		namespace debuger_present
		{
			bool check()
			{
				return IsDebuggerPresent();
			}
		}

		namespace remote_debuger
		{
			bool check()
			{
				BOOL result = false;
				CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
				if (result)
					return true;
				else
					return false;
			}
		}

		namespace ntglobal
		{
			bool check()
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

				bool normal_detected = nt_global_flag && *nt_global_flag & 0x00000070;
				bool wow64_detected = nt_global_flag_wow64 && *nt_global_flag_wow64 & 0x00000070;

				if (normal_detected || wow64_detected)
					return true;
				else
					return false;
			}
		}

		namespace being_debuged
		{
			bool check()
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
		}

		namespace heap
		{
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

			bool check()
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
		}

		namespace force
		{
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

			bool check()
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
		}
	}
}
