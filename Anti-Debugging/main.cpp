// Kaipod Offensive Research Project: Anti-Analysis Package
// Coded by Milad Kahsari Alhadi (clightning)
// http://kaipod.ir

#include "global.h"
#include "process_enum.h"
#include "information.h"

int main(int argc, const char argv[])
{
	print::red(NAME);
	std::cout << color_range::green << "\t[Project]:\t" << color_range::yellow << PROJECT << " " ARCHITECTURE << color_range::reset << "\n";
	std::cout << color_range::green << "\t[Address]:\t" << color_range::yellow << PAGE << color_range::reset << "\n\n";


	print::blue("Anti Debugging Check");
	print::red("Debug's Flags");
	print::result("\tCheckRemoteDebuggerPresent:\t", enumeration::remote_debuger_present());
	print::result("\tIsDebugerPresent:\t\t", enumeration::debuger_present());
	print::result("\tBeingDebuged Flag:\t\t", enumeration::being_debug_flag());
	print::result("\tNtGlobalFlag Flag:\t\t", enumeration::ntglobal_flag());
	print::result("\tProcess Heap Flags: \t\t", enumeration::heap_flags());
	print::result("\tProcess Heap Force Flags:\t", enumeration::heap_force_flags());
	print::result("\tDebug Port Check:\t\t", enumeration::process_debugport());
	print::result("\tProcess Debug Object:\t\t", enumeration::process_debug_object());

	print::break_line();
	print::red("Debugger's Process");
	print::result("\t[Ollydbg Process]:\t\t", enumeration::processes(L"ollydbg.exe"));
	print::result("\t[x32dbg Process]:\t\t", enumeration::processes(L"x32dbg.exe"));
	print::result("\t[x64dbg Process]:\t\t", enumeration::processes(L"x64dbg.exe"));

	
	std::cin.get();
	return 0;
}