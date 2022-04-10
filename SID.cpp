#include "SID.h"
#include <sddl.h>


Sid::Sid(PSID pSid) : m_data(::GetLengthSid(pSid))
{
    CALL_API(::CopySid(static_cast<DWORD>(m_data.size()), &m_data[0], pSid));
    get_name();
}

Sid::Sid(WELL_KNOWN_SID_TYPE sidType)
{
    DWORD size = 0;
    ::CreateWellKnownSid(sidType, nullptr, nullptr, &size);

    m_data.resize(size);
    CALL_API(::CreateWellKnownSid(sidType, nullptr, &m_data[0], &size));

    get_name();
}

Sid::Sid(const char* name) : m_name(name)
{
    PSID pSid = NULL;
    CALL_API(::ConvertStringSidToSidA(name, &pSid));

    OnScopeExit<> cleanup([pSid]() { ::LocalFree(pSid); });

    m_data.resize(::GetLengthSid(pSid));
    CALL_API(::CopySid(static_cast<DWORD>(m_data.size()), &m_data[0], pSid));
}

void Sid::get_name()
{
    char* name = nullptr;
    CALL_API(::ConvertSidToStringSidA(&m_data[0], &name));
    OnScopeExit<> cleanup([name]() { ::LocalFree(name); });
    
    m_name.assign(name);    
}
