#pragma once
#include <cstdint>
#include <cstring>
#include <vector>

inline std::vector<unsigned char> Fixture()
{
    std::vector<unsigned char> bytes(0x4000);
    auto word = [&](size_t at, uint16_t value) { std::memcpy(bytes.data() + at, &value, 2); };
    auto dword = [&](size_t at, uint32_t value) { std::memcpy(bytes.data() + at, &value, 4); };
    word(0, 0x5a4d); dword(60, 0x80); dword(0x80, 0x4550);
    word(0x84, 0x8664); word(0x86, 1); word(0x94, 240); word(0x98, 0x20b);
    dword(0x98 + 56, 0x4000); dword(0x98 + 108, 16);
    dword(0x98 + 112, 0x1000); dword(0x98 + 116, 0x300);
    dword(0x188 + 8, 0x1000); dword(0x188 + 12, 0x2000); dword(0x188 + 36, 0x60000020);
    dword(0x188 + 16, 0x1000);
    dword(0x100c, 0x1100); dword(0x1014, 2); dword(0x1018, 2);
    dword(0x101c, 0x1040); dword(0x1020, 0x1050); dword(0x1024, 0x1060);
    dword(0x1040, 0x2000); dword(0x1044, 0x2010);
    dword(0x1050, 0x1120); dword(0x1054, 0x1160); word(0x1060, 0); word(0x1062, 1);
    std::strcpy(reinterpret_cast<char*>(bytes.data() + 0x1100), "steam_api64.dll");
    std::strcpy(reinterpret_cast<char*>(bytes.data() + 0x1120), "SteamAPI_GetHSteamUser");
    std::strcpy(reinterpret_cast<char*>(bytes.data() + 0x1160), "SteamAPI_GetHSteamPipe");
    // Two independent x64 functions returning 7 and 9 before any redirect.
    const unsigned char first[] = {0xb8, 7, 0, 0, 0, 0xc3};
    const unsigned char second[] = {0xb8, 9, 0, 0, 0, 0xc3};
    std::memcpy(bytes.data() + 0x2000, first, sizeof first);
    std::memcpy(bytes.data() + 0x2010, second, sizeof second);
    return bytes;
}
