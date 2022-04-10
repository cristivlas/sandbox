#include "RestrictedTokenBuilder.h"

#include <iostream>
#include <sstream>


void execute(const std::wstring& CmdLine)
{
    if (!CmdLine.empty())
    {
        RestrictedTokenBuilder tokenBuilder;

        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        DWORD Flags = 0;

        CALL_API(::CreateProcessAsUserW(
            tokenBuilder.get_token(),
            nullptr,
            const_cast<wchar_t*>(CmdLine.c_str()),
            nullptr,
            nullptr,
            false,          // Do not inherit handles
            Flags,
            nullptr,        // Environment
            nullptr,        // Use parent's starting directory
            &si,            // Pointer to STARTUPINFO structure
            &pi             // Pointer to PROCESS_INFORMATION structure
        ));

         // Wait until child process exits.
        CALL_API(::WaitForSingleObject(pi.hProcess, INFINITE));

        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
    }
}

int wmain(int argc, const wchar_t* argv[])
{
    try
    {
        std::wostringstream CmdLineBuilder;

        bool FirstArg = true;
        for (--argc, ++argv; argc; --argc, ++argv, FirstArg = false)
        {
            if (FirstArg)
                CmdLineBuilder << L"\"" << *argv << L"\"";
            else
                CmdLineBuilder << L" " << *argv;
        }

        execute(CmdLineBuilder.str());
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}
