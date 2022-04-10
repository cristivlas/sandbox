#pragma once
#include "SID.h"

class RestrictedTokenBuilder
{
    static constexpr WELL_KNOWN_SID_TYPE Whitelist[] = {
        WinWorldSid,
        WinBuiltinUsersSid,
    };

public:
    RestrictedTokenBuilder();
    ~RestrictedTokenBuilder();

    HANDLE get_token();
    bool is_whitelisted(const Sid&) const;

private:
    void get_deny_only_sids(HANDLE);
    void get_privileges_to_remove(HANDLE);

    void set_integrity_level();

private:
    HANDLE m_hToken = INVALID_HANDLE_VALUE;

    std::vector<Sid> m_denyOnly;
    std::vector<LUID_AND_ATTRIBUTES> m_privileges;
};

