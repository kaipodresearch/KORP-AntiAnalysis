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
	
	}
}
