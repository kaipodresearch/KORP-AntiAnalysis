#pragma once

namespace breakpoint
{
	namespace software
	{
		void critical_function()
		{
			int variable_one = 1;
			int variable_two = 2;
			int variable_thr = variable_one + variable_two;
			std::printf("It is a function that should protect against CC opcode %d", variable_thr);
		}


		void adjacent_critical_function()
		{
			critical_function();
		};

		bool check()
		{
			size_t function_size = (size_t)(adjacent_critical_function)-(size_t)(critical_function);
			PUCHAR critical_procedure = (PUCHAR)critical_function;

			for (size_t i = 0; i < function_size; i++) {
				if (critical_procedure[i] == 0xCC)
					return true;
			}
			return false;
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
