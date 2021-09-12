#pragma once

namespace memory
{
	namespace page_guard
	{
		bool check()
		{
			UCHAR* memory_pointer = NULL;
			SYSTEM_INFO system_info = { 0 };
			DWORD old_protection = 0;
			PVOID allocation = NULL;

			GetSystemInfo(&system_info);

			allocation = VirtualAlloc(NULL, system_info.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			if (allocation == NULL)
			{
				return false;
			}

			RtlFillMemory(allocation, 1, 0xC3);

			if (VirtualProtect(allocation, system_info.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old_protection) == 0)
			{
				return false;
			}

			__try
			{
				((void(*)())allocation)();
			}
			__except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
			{
				VirtualFree(allocation, 0, MEM_RELEASE);
				return false;
			}

			VirtualFree(allocation, 0, MEM_RELEASE);
			return true;
		}
	}

	namespace read_access
	{
		std::vector<PVOID> executable_pages = {};

		bool check()
		{
			SYSTEM_INFO system_information;
			GetSystemInfo(&system_information);
			size_t page_size = system_information.dwPageSize;

			HMODULE main_module;
			MODULEINFO module_info;
			MEMORY_BASIC_INFORMATION memory_info = { 0 };

			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)check, &main_module))
			{
				if (GetModuleInformation(GetCurrentProcess(), main_module, &module_info, sizeof(MODULEINFO)))
				{
					unsigned char* module = static_cast<unsigned char*>(module_info.lpBaseOfDll);
					for (size_t offsets = 0; offsets < module_info.SizeOfImage; offsets += page_size)
					{
						if (VirtualQuery(module + offsets, &memory_info, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
						{
							if ((memory_info.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
								(memory_info.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
								(memory_info.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
								(memory_info.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
							{
								if ((memory_info.Protect & PAGE_GUARD) == PAGE_GUARD ||
									(memory_info.AllocationProtect & PAGE_GUARD) == PAGE_GUARD)
								{
									return true;
								}
							}

							if ((memory_info.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
							{
								return true;
							}
						}
						else
							return false;
					}
				}

				for (PVOID page : executable_pages)
				{
					if (VirtualQuery(page, &memory_info, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
					{
						if (!((memory_info.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
							(memory_info.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
							(memory_info.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
							(memory_info.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE))
						{
							return true;
						}
					}
				}
			}
			return false;
		}
	}
	namespace int2d
	{
		
	}
}