#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wdbgexts.h>
#include <winternl.h>
#include <VersionHelpers.h>


#include <iostream>
#include <vector>


#if _WIN32 || _WIN64
#if _WIN64
#define x64
#else
#define x86
#endif
#endif

#ifdef _DEBUG
#define ODebugString(S) OutputDebugString(S)
#else
#define ODebugString(S) do {} while(0);
#endif

enum class color_range : uint16_t {
    grey
    , blue
    , green
    , cyan
    , red
    , magenta
    , yellow
    , white
    , on_blue
    , on_red
    , on_magenta
    , on_grey
    , on_green
    , on_cyan
    , on_yellow
    , on_white
    , reset = 0xFF
};

namespace colored_cout_impl 
{
	uint16_t get_color_code(const color_range arg_color) 
    {
		switch (arg_color) 
        {
		case color_range::grey:         return FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;
		case color_range::blue:         return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
		case color_range::green:        return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		case color_range::cyan:         return FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		case color_range::red:          return FOREGROUND_RED | FOREGROUND_INTENSITY;
		case color_range::magenta:      return FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY;
		case color_range::yellow:       return FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
		case color_range::white:        return FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
		case color_range::on_blue:      return BACKGROUND_BLUE; //| BACKGROUND_INTENSITY
		case color_range::on_red:       return BACKGROUND_RED;  //| BACKGROUND_INTENSITY
		case color_range::on_magenta:   return BACKGROUND_BLUE | BACKGROUND_RED;  //| BACKGROUND_INTENSITY
		case color_range::on_grey:      return BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED;
		case color_range::on_green:     return BACKGROUND_GREEN | BACKGROUND_INTENSITY;
		case color_range::on_cyan:      return BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_INTENSITY;
		case color_range::on_yellow:    return BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY;
		case color_range::on_white:     return BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY;
		case color_range::reset:
		default: break;
		}
		return static_cast<uint16_t>(color_range::reset);
	}

	uint16_t get_console_attr() 
    {
		CONSOLE_SCREEN_BUFFER_INFO buffer_info;
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &buffer_info);
		return buffer_info.wAttributes;
	}

	void set_console_attr(const uint16_t attr) 
    {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
	}
}

template <typename type>
type& operator<<(type& arg_ostream, const color_range arg_color)
{
    static const uint16_t initial_attributes = colored_cout_impl::get_color_code(color_range::grey);
    static uint16_t background = initial_attributes & 0x00F0;
    static uint16_t foreground = initial_attributes & 0x000F;
    if (arg_color == color_range::reset)
    {
        arg_ostream.flush();
        colored_cout_impl::set_console_attr(initial_attributes);
        background = initial_attributes & 0x00F0;
        foreground = initial_attributes & 0x000F;
    }
    else 
    {
        uint16_t set = 0;
        const uint16_t color_code = colored_cout_impl::get_color_code(arg_color);
        if (color_code & 0x00F0)
        {
            background = color_code;
            set = background | foreground;
        }
        else if (color_code & 0x000F) 
        {
            foreground = color_code;
            set = background | foreground;
        }
        arg_ostream.flush();
        colored_cout_impl::set_console_attr(set);
    }
    return arg_ostream;
}


namespace print
{
    void red(std::string arg_caption)
    {
		std::cout << color_range::red << "\t[" << arg_caption << "]" << color_range::reset << "\n";
    }

	void blue(std::string arg_caption)
	{
		std::cout << color_range::blue << "\t[" << arg_caption << "]" << color_range::reset << "\n";
	}

    void result(std::string arg_caption, bool arg_result)
    {
        if (arg_result = true)
        {
            std::cout << color_range::green << "\t" << arg_caption << color_range::white << "Detected" << color_range::reset << "\n";
        }
        else
        {
			std::cout << color_range::green << "\t" << arg_caption << color_range::white << "Unknown" << color_range::reset << "\n";
        }
    }

    void break_line()
    {
        std::cout << std::endl;
    }

}



// Signature definition

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);