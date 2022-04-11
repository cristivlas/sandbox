#pragma once
#include "SID.h"

class RestrictedTokenBuilder
{
    static constexpr WELL_KNOWN_SID_TYPE SID_Whitelist[] = {
        WinWorldSid,
        WinBuiltinUsersSid,
        WinAuthenticatedUserSid,
    };

    static constexpr const wchar_t* Privilege_Whitelist[] = {
        SE_CHANGE_NOTIFY_NAME,
        SE_IMPERSONATE_NAME,
    };

public:
    RestrictedTokenBuilder();
    ~RestrictedTokenBuilder();

    HANDLE get_token();

private:
    RestrictedTokenBuilder(const RestrictedTokenBuilder&) = delete;
    RestrictedTokenBuilder& operator=(const RestrictedTokenBuilder&) = delete;

    void get_deny_only_sids(HANDLE);
    void get_privileges_to_remove(HANDLE);

    bool is_whitelisted_sid(const Sid&) const;
    bool is_whitelisted_privilege(const LUID&) const;

    void set_integrity_level();

private:
    HANDLE m_hToken = INVALID_HANDLE_VALUE;

    std::vector<Sid> m_denyOnly;
    std::vector<LUID_AND_ATTRIBUTES> m_privileges;
};

