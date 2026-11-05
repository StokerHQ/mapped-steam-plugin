# Mapped Steam library redirect

`app.stokerhq.mapped-steam`: a [Stoker](https://github.com/StokerHQ) hook plugin for a program that carries its own copy of
the Steamworks library and maps it into memory itself, instead of loading it through Windows' loader. Stoker's
bootstrap stands in for `steam_api64.dll` when Windows loads it; a privately mapped copy never reaches it. This plugin
points such a copy's exports at the loaded bootstrap.

## What it does

- Detours `VirtualProtect` and `GetProcAddress` in the process it runs in (only in `process`, when that is set).
- When a private, executable image appears whose export directory names `image`, it validates the image with bounded
  reads - machine, image size, sections, export tables, ordinals and terminated names - and leaves anything malformed,
  anything ordinary Windows loaded, and anything else alone.
- Each supported named code export gets a sixteen-byte jump above the image, to the bootstrap's export of the same name;
  shared original addresses stay intact, so different names reach different functions. Forwarded exports, and names
  sharing an ordinal, refuse the redirection. Data exports and unsupported legacy APIs are left as they are, and counted
  in the log.
- A named `GetProcAddress` lookup in such an image returns the bootstrap's export directly.

Windows x64 only.

## Options

| Option | | |
|---|---|---|
| `image` | optional | The DLL name in the private image's export directory; `steam_api64.dll` when left out. |
| `bootstrap` | optional | The loaded Stoker bootstrap that supplies the replacement exports; `steam_api64.dll` when left out. |
| `remoteStorageVersion` | optional | The layout an unversioned `SteamRemoteStorage` accessor returns; the bootstrap's legacy layout when left out. |
| `process` | optional | Only act inside this executable. |

## Tests

`tests/pe.cpp` checks the image reader against a synthetic image and its malformed and boundary variants; CI runs it
for x86 and x64.
## Releases

A release is tagged `v<version>`, the version the manifest in the source declares; CI refuses a tag that differs. The
release's assets are built by CI from the tagged commit (`mapped-steam-windows-x64.dll`) and are what the StokerHQ plugin registry
(`app.stokerhq.mapped-steam` in [StokerHQ/plugins](https://github.com/StokerHQ/plugins)) lists by SHA-256 and BLAKE3, signed by the
StokerHQ publisher key.

## Building

```powershell
./build.ps1
```

Needs Visual Studio with the C++ workload. The SDK is the release `stoker-plugin.yaml` pins, fetched once and checked by
SHA-256; `STOKER_PLUGIN_SDK` names a local SDK folder or zip instead.

## Licence

AGPL-3.0-or-later (`LICENSE`).