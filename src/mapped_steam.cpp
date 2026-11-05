// Shared function addresses cannot distinguish the API name requested by a game's private loader.
// Redirect export slots instead. Positive 32-bit RVAs can reach nearby x64 absolute-jump relays.
#include "stoker/plugin_support.h"

STOKER_PLUGIN_MANIFEST(R"json({
  "manifestVersion": 1,
  "id": "app.stokerhq.mapped-steam",
  "name": "Mapped Steam library redirect",
  "type": "hook",
  "version": "1.0.3",
  "abi": 1,
  "description": "Redirects supported exports of a privately mapped Steam library to Stoker's bootstrap, including manual loader layouts.",
  "hosts": ["steamworks"],
  "config": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "process": {
        "type": "string", "title": "Game executable",
        "description": "Only redirect inside this executable. Omit to act in every process. File name only, compared without regard to case.",
        "minLength": 1, "maxLength": 259, "pattern": "^(?!\\.{1,2}$)[^\\\\/:]+$", "examples": ["Game.exe"]
      },
      "image": {
        "type": "string", "title": "Embedded library name",
        "description": "The DLL name in the private image's export directory. File name only.",
        "default": "steam_api64.dll", "minLength": 1, "maxLength": 259, "pattern": "^(?!\\.{1,2}$)[^\\\\/:]+$"
      },
      "remoteStorageVersion": {
        "type": "string", "title": "Unversioned RemoteStorage interface",
        "description": "Override the layout returned by SteamRemoteStorage. Omit to keep the bootstrap's legacy layout.",
        "enum": ["012", "014", "016"]
      },
      "bootstrap": {
        "type": "string", "title": "Loaded bootstrap DLL",
        "description": "The loaded Stoker bootstrap that supplies replacement code exports. File name only.",
        "default": "steam_api64.dll", "minLength": 1, "maxLength": 259, "pattern": "^(?!\\.{1,2}$)[^\\\\/:]+$"
      }
    }
  }
})json");
#include "mapped_pe.h"
#ifdef _WIN32
#include <map>
#include <mutex>
#include <atomic>
namespace
{
    using stoker::plugin::Log;
    using ProtectFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    using LookupFn = FARPROC (WINAPI*)(HMODULE, LPCSTR);
    ProtectFn g_real = nullptr;
    LookupFn g_lookup = nullptr;
    HMODULE g_bootstrap = nullptr;
    using CreateInterfaceFn = void* (__cdecl*)(const char*);
    CreateInterfaceFn g_createInterface = nullptr;
    char g_storageVersion[48] = "";
    char g_image[MAX_PATH] = "steam_api64.dll";
    std::mutex g_mutex;
    thread_local bool g_inside = false;
    std::atomic<unsigned> g_diagnostics{0};

    void* __cdecl RemoteStorage()
    {
        return g_createInterface(g_storageVersion);
    }

    FARPROC Replacement(const char* name)
    {
        // An embedded SDK can export an unversioned accessor for layout 014. The shim's legacy
        // accessor serves 012: slots 18/19 are booleans there, where such a caller expects a
        // file count and a string. Keep the legacy layout unless remoteStorageVersion names
        // one, and resolve that version through the bootstrap's ordinary first-call path.
        if (g_createInterface && !std::strcmp(name, "SteamRemoteStorage"))
            return reinterpret_cast<FARPROC>(&RemoteStorage);
        return g_lookup(g_bootstrap, name);
    }

    bool Read(const unsigned char* base, uint32_t offset, void* output, size_t bytes)
    {
        SIZE_T actual = 0;
        return ReadProcessMemory(GetCurrentProcess(), base + offset, output, bytes, &actual) && actual == bytes;
    }

    void Diagnose(unsigned char* base)
    {
        uint32_t nt = 0, pe = 0, size = 0, exports = 0, name = 0;
        uint16_t machine = 0, magic = 0;
        if (!Read(base, 60, &nt, 4) || nt > 0x100000) return;
        Read(base, nt, &pe, 4); Read(base, nt + 4, &machine, 2); Read(base, nt + 24, &magic, 2);
        Read(base, nt + 80, &size, 4); Read(base, nt + 136, &exports, 4);
        char dll[64]{};
        if (size <= 16 * 1024 * 1024 && exports && exports < size - 40 && Read(base, exports + 12, &name, 4) && name < size)
            Read(base, name, dll, sizeof dll - 1);
        Log("mapped-steam: header nt=0x%lx pe=0x%lx machine=0x%x magic=0x%x size=0x%lx exports=0x%lx nameRva=0x%lx name=%s",
            nt, pe, machine, magic, size, exports, name, dll);
        // Opt-in local diagnosis only; ordinary game runs create no memory dump. A mapped file
        // differs from its embedded bytes after relocations and private-loader fixups. Capturing
        // those bytes makes parser failures reproducible without another run or unbounded logging.
        wchar_t directory[1024];
        const DWORD directoryLength = GetEnvironmentVariableW(L"STOKER_HOOK_DIAGNOSTICS", directory, 1024);
        if (!directoryLength || directoryLength >= 1024 || size < 4096 || size > 16 * 1024 * 1024) return;
        std::vector<unsigned char> snapshot(size);
        for (uint32_t offset = 0; offset < size; offset += 4096)
            Read(base, offset, snapshot.data() + offset, std::min<uint32_t>(4096, size - offset));
        wchar_t path[1280];
        swprintf_s(path, L"%ls\\mapped-steam-%lu-%u.bin", directory, GetCurrentProcessId(), g_diagnostics.load());
        const HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            DWORD written;
            WriteFile(file, snapshot.data(), size, &written, nullptr);
            CloseHandle(file);
        }
    }

    // This identity survives table redirection, unlike a strict parser requiring in-image RVAs.
    bool Identity(unsigned char* base)
    {
        uint16_t mz = 0, machine = 0, magic = 0;
        uint32_t nt = 0, pe = 0, size = 0, exports = 0, name = 0;
        if (!Read(base, 0, &mz, 2) || mz != 0x5a4d || !Read(base, 60, &nt, 4) || nt > 0x100000 ||
            !Read(base, nt, &pe, 4) || pe != 0x4550 || !Read(base, nt + 4, &machine, 2) || machine != 0x8664 ||
            !Read(base, nt + 24, &magic, 2) || magic != 0x20b || !Read(base, nt + 80, &size, 4) ||
            size < 4096 || size > 512 * 1024 * 1024 || !Read(base, nt + 136, &exports, 4) || !exports ||
            exports > size - 40 || !Read(base, exports + 12, &name, 4) || name >= size) return false;
        char actual[MAX_PATH]{};
        for (uint32_t i = 0; i < sizeof actual; ++i)
        {
            if (i >= size - name || !Read(base, name + i, actual + i, 1)) return false;
            if (!actual[i]) return std::strcmp(actual, g_image) == 0;
        }
        return false;
    }

    unsigned char* RelayAbove(unsigned char* image, uint32_t imageSize, size_t bytes)
    {
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        const uintptr_t base = reinterpret_cast<uintptr_t>(image), granularity = system.dwAllocationGranularity;
        uintptr_t cursor = (base + imageSize + granularity - 1) & ~(granularity - 1);
        const uintptr_t limit = std::min(base + UINT32_MAX - bytes,
            reinterpret_cast<uintptr_t>(system.lpMaximumApplicationAddress) - bytes);
        while (cursor < limit)
        {
            MEMORY_BASIC_INFORMATION region{};
            if (!VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof region)) return nullptr;
            if (region.State == MEM_FREE && region.RegionSize >= bytes)
                if (auto result = VirtualAlloc(reinterpret_cast<void*>(cursor), bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
                    return static_cast<unsigned char*>(result);
            const uintptr_t next = (reinterpret_cast<uintptr_t>(region.BaseAddress) + region.RegionSize + granularity - 1) & ~(granularity - 1);
            if (next <= cursor) return nullptr;
            cursor = next;
        }
        return nullptr;
    }

    void Redirect(unsigned char* base)
    {
        if (!Identity(base)) return;
        stoker::plugin::MappedPe image;
        if (!stoker::plugin::ReadMappedPe([&](uint32_t offset, void* out, size_t bytes) { return Read(base, offset, out, bytes); },
                                        g_image, 0x8664, image, reinterpret_cast<uintptr_t>(base))) return;
        struct Patch { uint32_t slot, after; void* target; };
        std::map<uint32_t, Patch> patches;
        size_t unsupported = 0;
        for (const auto& symbol : image.exports)
        {
            void* target = reinterpret_cast<void*>(Replacement(symbol.name.c_str()));
            // Old Steam SDKs export callback helpers and obsolete flat APIs absent from Stoker.
            // Do not let an unused legacy name block the ordinary API the game actually requests.
            if (!target) { ++unsupported; continue; }
            auto [entry, added] = patches.emplace(symbol.slot, Patch{symbol.slot, 0, target});
            if (!added && entry->second.target != target)
            { Log("mapped-steam: refusing different names sharing one export ordinal"); return; }
        }
        if (patches.empty()) return;
        // Allocate and preflight before changing any table protection. Code and data exports remain
        // untouched; each distinct ordinal receives its own relay even if original code is shared.
        struct Region { void* address; size_t bytes; DWORD protection; };
        std::map<uintptr_t, Region> regions;
        for (const auto& [slot, patch] : patches)
        {
            MEMORY_BASIC_INFORMATION region{};
            if (!VirtualQuery(base + slot, &region, sizeof region) || region.State != MEM_COMMIT ||
                region.AllocationBase != base || reinterpret_cast<uintptr_t>(base + slot + 4) >
                    reinterpret_cast<uintptr_t>(region.BaseAddress) + region.RegionSize) return;
            regions.emplace(reinterpret_cast<uintptr_t>(region.BaseAddress), Region{region.BaseAddress, region.RegionSize, region.Protect});
        }
        const size_t relayBytes = patches.size() * 16;
        auto relay = RelayAbove(base, image.size, relayBytes);
        if (!relay) { Log("mapped-steam: no storage within export RVA range"); return; }
        size_t index = 0;
        for (auto& [slot, patch] : patches)
        {
            auto stub = relay + index++ * 16;
            const unsigned char jump[] = {0xff, 0x25, 0, 0, 0, 0};
            std::memcpy(stub, jump, sizeof jump);
            std::memcpy(stub + 6, &patch.target, sizeof patch.target);
            patch.after = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stub) - reinterpret_cast<uintptr_t>(base));
        }
        DWORD old = 0;
        if (!g_real(relay, relayBytes, PAGE_EXECUTE_READ, &old) || !FlushInstructionCache(GetCurrentProcess(), relay, relayBytes))
        { VirtualFree(relay, 0, MEM_RELEASE); return; }
        bool writable = true;
        size_t changed = 0;
        for (const auto& [address, region] : regions)
        {
            const DWORD basic = region.protection & 0xff;
            const bool executable = basic == PAGE_EXECUTE || basic == PAGE_EXECUTE_READ ||
                                    basic == PAGE_EXECUTE_READWRITE || basic == PAGE_EXECUTE_WRITECOPY;
            if (!g_real(region.address, region.bytes, executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &old))
            { writable = false; break; }
            ++changed;
        }
        if (writable) for (const auto& [slot, patch] : patches) std::memcpy(base + slot, &patch.after, 4);
        size_t indexRegion = 0;
        for (const auto& [address, region] : regions)
        {
            if (indexRegion++ >= changed) break;
            if (!g_real(region.address, region.bytes, region.protection, &old)) Log("mapped-steam: could not restore export-page protection");
        }
        if (!writable) { VirtualFree(relay, 0, MEM_RELEASE); return; }
        Log("mapped-steam: redirected %zu export slots at %p; %zu unsupported exports left unchanged", patches.size(), base, unsupported);
    }

    BOOL WINAPI HookedProtect(LPVOID address, SIZE_T size, DWORD protection, PDWORD previous)
    {
        const BOOL result = g_real(address, size, protection, previous);
        const DWORD error = GetLastError();
        if (result && !g_inside)
        {
            g_inside = true;
            try
            {
                MEMORY_BASIC_INFORMATION region{};
                if (VirtualQuery(address, &region, sizeof region) && region.Type == MEM_PRIVATE)
                {
                    auto base = static_cast<unsigned char*>(region.AllocationBase);
                    uint16_t mz = 0;
                    if (Read(base, 0, &mz, 2) && mz == 0x5a4d)
                    {
                        if (g_diagnostics.fetch_add(1) < 16)
                        {
                            Log("mapped-steam: private PE protection at %p, base %p, size %zu, protection 0x%lx", address, base, size, protection);
                            Diagnose(base);
                        }
                        std::lock_guard lock(g_mutex);
                        Redirect(base);
                    }
                }
            }
            catch (...) { Log("mapped-steam: could not inspect mapped image"); }
            g_inside = false;
        }
        SetLastError(error);
        return result;
    }

    FARPROC WINAPI HookedLookup(HMODULE module, LPCSTR name)
    {
        const DWORD error = GetLastError();
        if (!g_inside && reinterpret_cast<uintptr_t>(name) > 65535)
        {
            g_inside = true;
            FARPROC target = nullptr;
            try
            {
                MEMORY_BASIC_INFORMATION region{};
                if (VirtualQuery(module, &region, sizeof region) && region.Type == MEM_PRIVATE &&
                    region.AllocationBase == module && Identity(reinterpret_cast<unsigned char*>(module)))
                {
                    if (std::strcmp(name, "g_pSteamClientGameServer")) target = Replacement(name);
                    if (target && g_diagnostics.fetch_add(1) < 32) Log("mapped-steam: redirected lookup %s", name);
                    if (!target && g_diagnostics.fetch_add(1) < 32) Log("mapped-steam: unsupported lookup %s; forwarding", name);
                }
            }
            catch (...) {}
            g_inside = false;
            SetLastError(error);
            if (target) return target;
        }
        return g_lookup(module, name);
    }
}
#endif

STOKER_HOOK_PLUGIN_ENTRY int STOKER_HOOK_CALL stoker_hook_plugin_init(const stoker_hook_host_v1* host)
{
    if (!stoker::plugin::Accept(host)) return STOKER_HOOK_UNSUPPORTED;
#if defined(_WIN32) && defined(_WIN64)
    bool here = false;
    if (!stoker::plugin::ForThisProcess(here)) return STOKER_HOOK_INVALID_ARGUMENT;
    if (!here) return STOKER_HOOK_OK;
    char bootstrap[MAX_PATH] = "steam_api64.dll";
    if (stoker::plugin::Option("image", g_image, sizeof g_image) == stoker::plugin::OptionRead::Invalid ||
        stoker::plugin::Option("bootstrap", bootstrap, sizeof bootstrap) == stoker::plugin::OptionRead::Invalid ||
        !stoker::plugin::PlainFileName(g_image) || !stoker::plugin::PlainFileName(bootstrap)) return STOKER_HOOK_INVALID_ARGUMENT;
    wchar_t module[MAX_PATH];
    if (!stoker::plugin::Wide(bootstrap, module, MAX_PATH) || !(g_bootstrap = GetModuleHandleW(module))) return STOKER_HOOK_NOT_FOUND;
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(g_bootstrap), &pinned)) return STOKER_HOOK_ERROR;
    char storage[4] = "";
    const auto storageRead = stoker::plugin::Option("remoteStorageVersion", storage, sizeof storage);
    if (storageRead == stoker::plugin::OptionRead::Invalid) return STOKER_HOOK_INVALID_ARGUMENT;
    if (storageRead == stoker::plugin::OptionRead::Present)
    {
        if (std::strcmp(storage, "012") && std::strcmp(storage, "014") && std::strcmp(storage, "016"))
            return STOKER_HOOK_INVALID_ARGUMENT;
        std::snprintf(g_storageVersion, sizeof g_storageVersion, "STEAMREMOTESTORAGE_INTERFACE_VERSION%s", storage);
        g_createInterface = reinterpret_cast<CreateInterfaceFn>(GetProcAddress(g_bootstrap, "SteamInternal_CreateInterface"));
        if (!g_createInterface) return STOKER_HOOK_NOT_FOUND;
        Log("mapped-steam: SteamRemoteStorage uses interface %s", storage);
    }
    Log("mapped-steam: watching all section protections and named lookups for private %s", g_image);
    // The lookup original must exist before the protection detour uses it to resolve bootstrap names.
    int result = host->hook_export(host->user, "kernel32.dll", "GetProcAddress", reinterpret_cast<void*>(&HookedLookup),
                                   reinterpret_cast<void**>(&g_lookup));
    if (result != STOKER_HOOK_OK) return result;
    return host->hook_export(host->user, "kernel32.dll", "VirtualProtect", reinterpret_cast<void*>(&HookedProtect),
                             reinterpret_cast<void**>(&g_real));
#else
    host->log(host->user, "mapped-steam requires Windows x64 (including Proton); no POSIX detour backend yet");
    return STOKER_HOOK_UNSUPPORTED;
#endif
}
