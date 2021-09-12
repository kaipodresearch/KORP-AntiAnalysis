#pragma once

namespace interrupt
{
	namespace int0x1
	{
		bool check()
		{
			bool detected = false;
			__try
			{
				__asm
				{
					pushfd
					or dword ptr[esp], 0x100
					popfd
					nop
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return false;
			}
			
			return true;
		}
	}

	namespace int0x2
	{
		bool check()
		{
			__try
			{
				__asm
				{
					xor eax, eax
					int 0x2d
					nop
				}
				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return false;
			}
		}
	}
}
