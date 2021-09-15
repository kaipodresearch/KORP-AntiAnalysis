#pragma once

#include <intrin.h>

namespace breakpoint
{
	namespace software
	{
		bool check()
		{
			bool result = false;

			PSAPI_WORKING_SET_INFORMATION working_set_info;
			QueryWorkingSet(GetCurrentProcess(), &working_set_info, sizeof(working_set_info));
			DWORD required_size = sizeof(PSAPI_WORKING_SET_INFORMATION) * (working_set_info.NumberOfEntries + 20);
			PPSAPI_WORKING_SET_INFORMATION p_working_set_info = (PPSAPI_WORKING_SET_INFORMATION)VirtualAlloc(0, required_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			QueryWorkingSet(GetCurrentProcess(), p_working_set_info, required_size);
			for (SIZE_T i = 0; i < p_working_set_info->NumberOfEntries; i++)
			{
				PVOID physical_address = (PVOID)(p_working_set_info->WorkingSetInfo[i].VirtualPage * 4096);
				MEMORY_BASIC_INFORMATION memory_info;
				VirtualQuery((PVOID)physical_address, &memory_info, sizeof(memory_info));
				if (memory_info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
				{
					if ((p_working_set_info->WorkingSetInfo[i].Shared == 0) || (p_working_set_info->WorkingSetInfo[i].ShareCount == 0))
					{
						result = true;
						break;
					}
				}
			}

			return result;
		}
	}

	namespace hardware
	{
		bool check()
		{
			bool result = false;
			PCONTEXT context = PCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));

			if (context) 
			{
				SecureZeroMemory(context, sizeof(CONTEXT));
				context->ContextFlags = CONTEXT_DEBUG_REGISTERS;
				if (GetThreadContext(GetCurrentThread(), context)) 
				{
					if (context->Dr0 != 0 || context->Dr1 != 0 || context->Dr2 != 0 || context->Dr3 != 0)
					{
						result = true;
					}
				}

				VirtualFree(context, 0, MEM_RELEASE);
			}

			return result;
		}
	}
}
