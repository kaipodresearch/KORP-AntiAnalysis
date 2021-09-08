// Kaipod Offensive Research Project: Anti-Analysis Package
// Coded by Milad Kahsari Alhadi (clightning)
// http://kaipod.ir

#include "global.h"
#include "information.h"
#include "process_enum.h"
#include "pe_flags.h"
#include "breakpoints.h"
#include "page_guard.h"

int main(int argc, const char argv[])
{
	print::red(NAME);
	std::cout << color_range::green << "\t[ Project ]:\t" << color_range::yellow << PROJECT << " " ARCHITECTURE << color_range::reset << "\n";
	std::cout << color_range::green << "\t[ Address ]:\t" << color_range::yellow << PAGE << color_range::reset << "\n";
	std::cout << color_range::green << "\t[ Coder   ]:\t" << color_range::yellow << "Milad Kahsari Alhadi - clightning" << color_range::reset << "\n\n";

	print::blue("Anti-Debugging Solutions:");
	print::red("Debugger's Flags");
	print::result("\tCheckRemoteDebuggerPresent:\t", enumeration::remote_debuger::check());
	print::result("\tIsDebugerPresent:\t\t", enumeration::debuger_present::check());
	print::result("\tBeingDebuged Flag:\t\t", pe::flags::being_debuged::check());
	print::result("\tNtGlobalFlag Flag:\t\t", pe::flags::ntglobal::check());
	print::result("\tProcess Heap Flags: \t\t", pe::flags::heap::check());
	print::result("\tProcess Heap Force Flags:\t", pe::flags::force::check());
	print::result("\tDebug Port Check:\t\t", pe::flags::debug_port::check());
	print::result("\tProcess Debug Object:\t\t", pe::flags::debug_object::check());
	print::break_line();

	print::red("Debugger's Process");
	print::result("\t[Ollydbg Process]:\t\t", enumeration::check(L"ollydbg.exe"));
	print::result("\t[x32dbg Process]:\t\t", enumeration::check(L"x32dbg.exe"));
	print::result("\t[x64dbg Process]:\t\t", enumeration::check(L"x64dbg.exe"));
	print::break_line();
	
	print::red("Debugger's Breakpoint");
	print::result("\tSoftware Breakpoint:\t\t", breakpoint::software::check());
	print::result("\tHardware Breakpoint:\t\t", breakpoint::software::check());

	print::break_line();

	print::red("Debugger's Memory Check");
	print::result("\tPage Guard Protection:\t\t", memory::page_guard::check());
	print::result("\tRead Memory Access:\t\t", memory::read_access::check());

	print::break_line();

	std::cin.get();
	return 0;
}