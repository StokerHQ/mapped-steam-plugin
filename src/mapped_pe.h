// Bounded reads of a mapped PE, shared by the Windows detour and portable malformed-image tests.
// File offsets are never used here: the loader has already arranged sections by virtual address.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace stoker::plugin
{
    struct MappedExport { std::string name; uint32_t rva; uint32_t room; uint32_t slot; };
    struct MappedPe { uint32_t size = 0; std::vector<MappedExport> exports; };

    template<class Reader>
    bool ReadMappedPe(Reader read, const char* wanted, uint16_t machine, MappedPe& result, uint64_t mappedAddress = 0)
    {
        result = {};
        auto word = [&](uint32_t offset, uint16_t& value) { return read(offset, &value, sizeof value); };
        auto dword = [&](uint32_t offset, uint32_t& value) { return read(offset, &value, sizeof value); };
        uint16_t signature = 0, actualMachine = 0, sections = 0, optionalSize = 0, magic = 0;
        uint32_t nt = 0, pe = 0, size = 0;
        if (!word(0, signature) || signature != 0x5a4d || !dword(60, nt) || nt > 0x100000 ||
            !dword(nt, pe) || pe != 0x4550 || !word(nt + 4, actualMachine) || actualMachine != machine ||
            !word(nt + 6, sections) || !sections || sections > 96 || !word(nt + 20, optionalSize) ||
            !word(nt + 24, magic) || magic != (machine == 0x8664 ? 0x20b : 0x10b) ||
            !dword(nt + 24 + 56, size) || size < 4096 || size > 512 * 1024 * 1024) return false;
        auto range = [&](uint32_t offset, uint64_t bytes) { return offset < size && bytes <= size - offset; };
        const uint32_t directory = nt + 24 + (magic == 0x20b ? 112 : 96);
        uint32_t count = 0, exportRva = 0, exportSize = 0;
        if (optionalSize < (magic == 0x20b ? 120 : 104) || !range(nt, 24 + optionalSize + sections * 40u) ||
            !dword(directory - 4, count) || !count || !dword(directory, exportRva) ||
            !dword(directory + 4, exportSize) || exportSize < 40 || !range(exportRva, exportSize)) return false;
        auto string = [&](uint32_t offset, std::string& value)
        {
            value.clear();
            for (uint32_t i = 0; i < 256; ++i)
            {
                char c;
                if (!range(offset, i + 1) || !read(offset + i, &c, 1)) return false;
                if (!c) return !value.empty();
                value += c;
            }
            return false;
        };
        uint32_t name = 0, functions = 0, names = 0, addresses = 0, strings = 0, ordinals = 0;
        std::string dll;
        if (!dword(exportRva + 12, name) || !string(name, dll) || dll != wanted ||
            !dword(exportRva + 20, functions) || !functions || functions > 8192 ||
            !dword(exportRva + 24, names) || !names || names > functions ||
            !dword(exportRva + 28, addresses) || !range(addresses, functions * 4u) ||
            !dword(exportRva + 32, strings) || !range(strings, names * 4u) ||
            !dword(exportRva + 36, ordinals) || !range(ordinals, names * 2u)) return false;
        struct Section { uint32_t begin, end; };
        std::vector<Section> code;
        for (uint32_t i = 0; i < sections; ++i)
        {
            const uint32_t section = nt + 24 + optionalSize + i * 40;
            uint32_t length = 0, begin = 0, flags = 0;
            if (!dword(section + 8, length) || !dword(section + 12, begin) || !dword(section + 36, flags)) return false;
            if (length && !range(begin, length))
            {
                // A MemoryModule-style loader can repurpose Misc.PhysicalAddress/VirtualSize
                // as the low 32 bits of its mapped section pointer. Accept only an exact match to
                // this image's real address; arbitrary out-of-range lengths remain malformed.
                // Executable bytes came from SizeOfRawData, whose bounded span still classifies
                // code exports without rewriting the game's modified header or guessing a size.
                if (!mappedAddress || length != static_cast<uint32_t>(mappedAddress + begin) ||
                    !dword(section + 16, length) || (length && !range(begin, length))) return false;
            }
            if (flags & 0x20000000) code.push_back({begin, begin + length});
        }
        std::vector<uint32_t> starts(functions);
        if (!read(addresses, starts.data(), functions * 4u)) return false;
        auto sorted = starts;
        std::sort(sorted.begin(), sorted.end());
        for (uint32_t i = 0; i < names; ++i)
        {
            uint16_t ordinal = 0;
            std::string symbol;
            if (!dword(strings + i * 4, name) || !string(name, symbol) ||
                !word(ordinals + i * 2, ordinal) || ordinal >= functions) return false;
            const uint32_t rva = starts[ordinal];
            if (!rva || !range(rva, 1)) return false;
            // A forwarder is a string rather than code. Data exports must retain their semantics.
            if (rva >= exportRva && rva - exportRva < exportSize) return false;
            const auto section = std::find_if(code.begin(), code.end(), [&](auto s) { return rva >= s.begin && rva < s.end; });
            if (section == code.end()) continue;
            const auto next = std::upper_bound(sorted.begin(), sorted.end(), rva);
            const uint32_t end = next == sorted.end() ? section->end : std::min(section->end, *next);
            result.exports.push_back({std::move(symbol), rva, end - rva, addresses + ordinal * 4u});
        }
        result.size = size;
        return !result.exports.empty();
    }
}
