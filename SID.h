#pragma once
#include "Common.h"
#include <string>
#include <vector>

class Sid
{
public:
    explicit Sid(PSID);
    explicit Sid(WELL_KNOWN_SID_TYPE);
    explicit Sid(const char*);

    operator PSID() const
    {
        return m_data.empty() ? nullptr : reinterpret_cast<PSID>(const_cast<BYTE*>(&m_data[0]));
    }

    const char* name() const
    {
        return m_name.c_str();
    }

    size_t size() const
    {
        return m_data.size();
    }

private:
    void get_name();

private:
    std::vector<BYTE> m_data;
    std::string m_name;
};

