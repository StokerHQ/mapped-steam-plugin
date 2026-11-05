#include "../src/mapped_pe.h"
#include "image_fixture.h"
#include <cassert>
#include <cstdio>

int main()
{
    auto bytes = Fixture();
    stoker::plugin::MappedPe image;
    auto parse = [&] { return stoker::plugin::ReadMappedPe([&](uint32_t at, void* out, size_t count) {
        if (at > bytes.size() || count > bytes.size() - at) return false;
        std::memcpy(out, bytes.data() + at, count); return true;
    }, "steam_api64.dll", 0x8664, image); };
    assert(parse() && image.exports.size() == 2 && image.exports[0].room == 16);
    const auto original = bytes;
    auto dword = [&](size_t at, uint32_t value) { std::memcpy(bytes.data() + at, &value, 4); };
    bytes[0] = 0; assert(!parse()); bytes = original;
    dword(60, 0xffffffff); assert(!parse()); bytes = original;
    bytes[0x84] = 0x4c; assert(!parse()); bytes = original;
    dword(0x98 + 56, 0xffffffff); assert(!parse()); bytes = original;
    dword(0x1018, 8193); assert(!parse()); bytes = original;
    dword(0x1050, 0x3fff); bytes[0x3fff] = 'x'; assert(!parse()); bytes = original;
    bytes[0x1060] = 2; assert(!parse()); bytes = original;
    dword(0x1040, 0x1100); assert(!parse()); bytes = original;
    bytes[0x1100] = 'X'; assert(!parse()); bytes = original;
    dword(0x1044, 0x2003); assert(parse() && image.exports[0].room == 3); bytes = original;
    dword(0x188 + 8, 0x3b402000);
    assert(!parse());
    auto mapped = [&](uint64_t address) { return stoker::plugin::ReadMappedPe([&](uint32_t at, void* out, size_t count) {
        if (at > bytes.size() || count > bytes.size() - at) return false;
        std::memcpy(out, bytes.data() + at, count); return true;
    }, "steam_api64.dll", 0x8664, image, address); };
    assert(mapped(0x3b400000) && image.exports[0].room == 16);
    assert(!mapped(0x3b410000));
    dword(0x188 + 16, 0xffffffff); assert(!mapped(0x3b400000)); bytes = original;
    bytes.resize(0x1000); assert(!parse());
    std::puts("Portable mapped PE tests passed (11 malformed/boundary cases).");
}
