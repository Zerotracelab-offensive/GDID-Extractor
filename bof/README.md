# get_gdid bof

A COFFLoader Beacon Object File that reports the Windows **GDID** (Global Device Identifier, a.k.a. Passport Unique ID / PUID) and 
the full set of hardware descriptors that `wlidsvc.dll` sends to `login.live.com/ppsecure/deviceaddcredential.srf` when the device is first provisioned.

## Toolchain

| Target | Compiler | Package (Debian/Ubuntu) | Package (Arch) |
|---|---|---|---|
| x64 (`get_gdid.x64.o`) | `x86_64-w64-mingw32-gcc` | `mingw-w64` | `mingw-w64-gcc` |
| x86 (`get_gdid.x86.o`) | `i686-w64-mingw32-gcc` | `mingw-w64` | `mingw-w64-gcc` |

## Command

```sh
make                
make get_gdid.x64.o
make clean
```

Or invoke the compiler directly:

```sh
x86_64-w64-mingw32-gcc -c -Os -fno-asynchronous-unwind-tables -masm=intel \
    -fno-stack-protector -mno-stack-arg-probe -Wall get_gdid.c \
    -o get_gdid.x64.o
```

The flags matter: `-mno-stack-arg-probe` avoids `___chkstk_ms` external
references that the beacon loader won't resolve; `-fno-stack-protector` avoids
`__stack_chk_fail`.

## Verification

```sh
x86_64-w64-mingw32-objdump -t get_gdid.x64.o | grep '\$'
```

Expected imports:

```
__imp_Advapi32$RegOpenKeyExW
__imp_Advapi32$RegQueryValueExW
__imp_Advapi32$RegEnumKeyExW
__imp_Advapi32$RegCloseKey
__imp_Kernel32$CreateFileW
__imp_Kernel32$DeviceIoControl
__imp_Kernel32$CloseHandle
__imp_Kernel32$GetLastError
__imp_Kernel32$LocalAlloc
__imp_Kernel32$LocalFree
__imp_Kernel32$WideCharToMultiByte
__imp_Kernel32$GetSystemFirmwareTable
__imp_Ncrypt$NCryptOpenStorageProvider
__imp_Ncrypt$NCryptGetProperty
__imp_Ncrypt$NCryptFreeObject
__imp_Bcrypt$BCryptOpenAlgorithmProvider
__imp_Bcrypt$BCryptCloseAlgorithmProvider
__imp_Bcrypt$BCryptCreateHash
__imp_Bcrypt$BCryptDestroyHash
__imp_Bcrypt$BCryptHashData
__imp_Bcrypt$BCryptFinishHash
__imp_Iphlpapi$GetAdaptersAddresses
__imp_BeaconPrintf
```

Entry symbol: `go` on x64, `_go` on x86.
