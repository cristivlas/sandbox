#include "RestrictedTokenBuilder.h"

#include <iostream>
#include <sstream>


static void assign_process_to_job(HANDLE hJob, HANDLE hProcess)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
    jeli.BasicLimitInformation.LimitFlags =
          JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_SCHEDULING_CLASS;

    CALL_API(::SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof jeli));

    JOBOBJECT_BASIC_UI_RESTRICTIONS ui_restrict = {
          JOB_OBJECT_UILIMIT_DESKTOP
        | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
        | JOB_OBJECT_UILIMIT_GLOBALATOMS
        | JOB_OBJECT_UILIMIT_HANDLES
        | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
        | JOB_OBJECT_UILIMIT_READCLIPBOARD
        | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
    };
    CALL_API(::SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &ui_restrict, sizeof ui_restrict));

    CALL_API(::AssignProcessToJobObject(hJob, hProcess));
}


static void execute(const std::wstring& CmdLine)
{
    if (!CmdLine.empty())
    {
        HANDLE hJob = ::CreateJobObject(nullptr, nullptr);
        if (!hJob)
            ThrowError("CreateJobObject");

        RestrictedTokenBuilder tokenBuilder;

        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        DWORD Flags = 0;

        OnScopeExit<> cleanup([&]() {
            if (pi.hThread)
                ::CloseHandle(pi.hThread);
            if (pi.hProcess)
                ::CloseHandle(pi.hProcess);
            ::CloseHandle(hJob);
        });

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

        assign_process_to_job(hJob, pi.hProcess);

        // Wait until child process exits.
        CALL_API(::WaitForSingleObject(pi.hProcess, INFINITE));
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
