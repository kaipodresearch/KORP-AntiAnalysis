//
// Kaipod Offensive Research Project: Anti-Analysis Package
// Coded by Milad Kahsari Alhadi (clightning)
// http://kaipod.ir
// 

#include "global.h"
#include "information.h"
#include "pe_flags.h"
#include "breakpoints.h"
#include "page_guard.h"
#include "verification.h"
#include "interrupt.h"
#include "pe_info.h"


int main(int argc, const char argv[])
{
	print::red(NAME);
	std::cout << color_range::green << "\t[ Project ]:\t" << color_range::yellow << PROJECT << " " ARCHITECTURE << color_range::reset << "\n";
	std::cout << color_range::green << "\t[ Address ]:\t" << color_range::yellow << PAGE << color_range::reset << "\n";
	std::cout << color_range::green << "\t[ Coder   ]:\t" << color_range::yellow << "Milad Kahsari Alhadi - clightning" << color_range::reset << "\n\n";

	print::blue("Anti-Debugging Solutions:");
	print::red("Debugger's Flags");
	print::result("\tIsDebuggerPresent:\t\t\t", pe::flags::debuger_present::check());
	print::result("\tBeingDebuged Flag:\t\t\t", pe::flags::being_debuged::check());
	print::result("\tNtGlobalFlag Flag:\t\t\t", pe::flags::ntglobal::check());
	print::result("\tProcess Heap Flags: \t\t\t", pe::flags::heap::check());
	print::result("\tProcess Heap Force Flags:\t\t", pe::flags::force::check());
	print::result("\tCheck Remote Debugger Present:\t\t", pe::flags::remote_debuger::check());
	print::break_line();

	print::red("Debugger's Breakpoint");
	print::result("\tSoftware Breakpoint:\t\t\t", breakpoint::software::check());
	print::result("\tHardware Breakpoint:\t\t\t", breakpoint::hardware::check());
	print::break_line();

	print::red("Debugger's Memory Modification");
	print::result("\tPage Guard Protection:\t\t\t", memory::page_guard::check());
	print::result("\tRead Memory Access:\t\t\t", memory::read_access::check());
	print::break_line();

	print::red("CPU's Interrupts and Registers");
	print::result("\tCatch Interrupt 0x1:\t\t\t", interrupt::int0x1::check());
	print::result("\tCatch Interrupt 0x2:\t\t\t", interrupt::int0x2::check());
	print::break_line();

	print::red("Internal Structure of PE");
	print::result("\tProcess - Debug Port Check:\t\t", os::processes::debug_port::check());
	print::result("\tProcess - Debug Object Check:\t\t", os::processes::debug_object::check());
	print::result("\tProcess - Debug Inherit Check:\t\t", os::processes::debug_inherit::check());
	print::result("\tThreads - Hide from Debugger Check:\t", os::threads::info_class::check());
	print::break_line();

	print::red("Process List Enumeration");
	print::result("\tOllydbg Process:\t\t\t", os::processes::enumeration::list(L"ollydbg.exe"));
	print::result("\tx32dbg  Process:\t\t\t", os::processes::enumeration::list(L"x32dbg.exe"));
	print::result("\tx64dbg  Process:\t\t\t", os::processes::enumeration::list(L"x64dbg.exe"));
	print::result("\txImmDbg Process:\t\t\t", os::processes::enumeration::list(L"ImmunityDebugger.exe"));
	print::result("\tDebugers Window:\t\t\t", os::processes::gui::check());
	print::break_line();

	return 0;
}