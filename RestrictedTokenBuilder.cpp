#include "RestrictedTokenBuilder.h"
#include <iostream>

RestrictedTokenBuilder::RestrictedTokenBuilder()
{
}

RestrictedTokenBuilder::~RestrictedTokenBuilder()
{
    if (m_hToken != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(m_hToken);
    }
}

HANDLE RestrictedTokenBuilder::get_token()
{
    if (m_hToken == INVALID_HANDLE_VALUE)
    {
        HANDLE hBaseToken = INVALID_HANDLE_VALUE;
        CALL_API(::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &hBaseToken));

        OnScopeExit<> cleanup([hBaseToken]() { ::CloseHandle(hBaseToken); });

        get_deny_only_sids(hBaseToken);
        get_privileges_to_remove(hBaseToken);

        DWORD flags = SANDBOX_INERT;

        std::vector<SID_AND_ATTRIBUTES> denyOnly;
        for (const auto& sid : m_denyOnly)
        {
            denyOnly.emplace_back(SID_AND_ATTRIBUTES{ sid, SE_GROUP_USE_FOR_DENY_ONLY });
        }

        CALL_API(::CreateRestrictedToken(hBaseToken, flags, 
            static_cast<DWORD>(denyOnly.size()),
            denyOnly.size() ? &denyOnly[0] : nullptr, 
            static_cast<DWORD>(m_privileges.size()),
            m_privileges.size() ? &m_privileges[0] : nullptr,
            0,
            nullptr,
            &m_hToken));

        set_integrity_level();
    }

    return m_hToken;
}

void RestrictedTokenBuilder::get_deny_only_sids(HANDLE hToken)
{
    DWORD size = 0;

    // First call determines the amount of memory that's needed
    ::GetTokenInformation(hToken, TokenGroups, nullptr, 0, &size);

    if (!size)
        ThrowError("GetTokenInformation(TokenGroups)");

    LocalMemory tokenInfo(size);

    CALL_API(::GetTokenInformation(hToken, TokenGroups, tokenInfo.get(), size, &size));
    auto pGroups = static_cast<PTOKEN_GROUPS>(tokenInfo);

    for (DWORD i = 0; i < pGroups->GroupCount; ++i)
    {
        const auto& Group = pGroups->Groups[i];
        if (   (Group.Attributes & SE_GROUP_LOGON_ID) == 0
            && (Group.Attributes & SE_GROUP_INTEGRITY) == 0)
        {
            Sid sid(Group.Sid);
            if (is_whitelisted_sid(sid))
                continue;

            m_denyOnly.emplace_back(sid);
        }
    }
}

void RestrictedTokenBuilder::get_privileges_to_remove(HANDLE hToken)
{
    DWORD size = 0;

    ::GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);

    if (!size)
        ThrowError("GetTokenInformation(TokenPrivileges)");

    LocalMemory tokenInfo(size);

    CALL_API(::GetTokenInformation(hToken, TokenPrivileges, tokenInfo.get(), size, &size));
    auto pPriv = static_cast<PTOKEN_PRIVILEGES>(tokenInfo);

    for (DWORD i = 0; i < pPriv->PrivilegeCount; ++i)
    {
        if (is_whitelisted_privilege(pPriv->Privileges[i].Luid))
            continue;

        m_privileges.emplace_back(pPriv->Privileges[i]);
    }
}

bool RestrictedTokenBuilder::is_whitelisted_sid(const Sid& sid) const
{
    for (const auto known_type : SID_Whitelist)
    {
        if (::IsWellKnownSid(sid, known_type))
        {
            // std::cout << sid.name() << "\n";
            return true;
        }
    }
    return false;
}

bool RestrictedTokenBuilder::is_whitelisted_privilege(const LUID& priv_luid) const
{
    for (const auto& ok_luid : Privilege_Whitelist)
    {
        LUID luid = {};
        CALL_API(::LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &luid));

        if (luid.LowPart == priv_luid.LowPart && luid.HighPart == priv_luid.HighPart)
            return true;
    }
    return false;
}

/*
https://redcanary.com/blog/process-integrity-levels/
 
S-1-16-0        Untrusted           Anonymous logged on processes. Write access is mostly blocked. Seen with Chrome.

S-1-16-4096     Low                 Used for AppContainers, browsers that access the internet and prevent most write
                                    access to objects on the system—specifically the registry and filesystem

S-1-16-8192     Medium              Default for most processes. For authenticated users.

S-1-16-8448     Medium Plus

S-1-16-12288    High                Administrator-level processes. (Elevated) process with UAC.

S-1-16-16384    System              Reserved for system services/processes
S-1-16-20480    Protected Process   Reserved for DRM and Anti-Malware Services/Protected Process Light processes

S-1-16-28672    Secure Process

*/

void RestrictedTokenBuilder::set_integrity_level()
{
    Sid sid("S-1-16-8192");

    TOKEN_MANDATORY_LABEL tml { sid, SE_GROUP_INTEGRITY };

    const DWORD size = sizeof(tml) + static_cast<DWORD>(sid.size());

    CALL_API(::SetTokenInformation(m_hToken, TokenIntegrityLevel, &tml, size));
}
