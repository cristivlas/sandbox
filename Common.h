#pragma once

#include <Windows.h>
#include <functional>
#include <string>
#include <stdexcept>

#define XSTR(x) #x
#define CALL_API(f) APICall(XSTR(f), f)


inline void ThrowError(const std::string& FuncName)
{
    throw std::runtime_error(FuncName + ": error=" + std::to_string(::GetLastError()));
}

inline BOOL APICall(const char* fname, BOOL result)
{
    if (!result)
        ThrowError(fname);
    return result;
}

inline DWORD APICall(const char* fname, DWORD result)
{
    if (result != ERROR_SUCCESS)
        ThrowError(fname);
    return result;
}


class LocalMemory
{
public:
    explicit LocalMemory(size_t nbytes)
        : m_hMem(::LocalAlloc(LMEM_FIXED, nbytes))
    {
        if (!m_hMem)
            ThrowError("LocalAlloc(" + std::to_string(nbytes) + ") failed.");
    }

    ~LocalMemory()
    {
        ::LocalFree(m_hMem);
    }

    void* get() const
    {
        return m_hMem;
    }

    template<typename T> explicit operator T* ()
    {
        return reinterpret_cast<T*>(get());
    }

private:
    LocalMemory(const LocalMemory&) = delete;
    LocalMemory& operator=(const LocalMemory&) = delete;

    const HLOCAL m_hMem;
};


template <typename F = std::function<void()>> class OnScopeExit
{
public:
    OnScopeExit(F&& f)
        : m_f(f)
    {
    }
    ~OnScopeExit() noexcept(false)
    {
        if (m_f)
            m_f();
    }

    OnScopeExit(OnScopeExit&& other)
    {
        std::swap(m_f, other.m_f);
    }

private:
    OnScopeExit(const OnScopeExit&);
    OnScopeExit& operator=(OnScopeExit&);

    F m_f;
};
