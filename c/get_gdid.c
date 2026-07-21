#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winioctl.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

#ifndef LSTATUS
typedef LONG LSTATUS;
#endif
#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif
#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef _O_U8TEXT
#define _O_U8TEXT 0x00040000
#endif
#ifndef NCRYPT_PCP_EKPUB_PROPERTY
#define NCRYPT_PCP_EKPUB_PROPERTY L"PCP_EKPUB"
#endif
#ifndef MS_PLATFORM_CRYPTO_PROVIDER
#define MS_PLATFORM_CRYPTO_PROVIDER L"Microsoft Platform Crypto Provider"
#endif
#ifndef GAA_FLAG_INCLUDE_ALL_INTERFACES
#define GAA_FLAG_INCLUDE_ALL_INTERFACES 0x0100
#endif

#define IDCRL_EXTPROPS L"SOFTWARE\\Microsoft\\IdentityCRL\\ExtendedProperties"
#define IDCRL_ROOT L"SOFTWARE\\Microsoft\\IdentityCRL"
#define IDCRL_NEGCACHE L"SOFTWARE\\Microsoft\\IdentityCRL\\NegativeCache"
#define HW_CONFIG L"SYSTEM\\HardwareConfig\\Current"

#define SMBIOS_PROVIDER 0x52534D42u /* 'RSMB' as a DWORD */

static BOOL reg_read_sz(HKEY root, LPCWSTR subkey, LPCWSTR value,
                        wchar_t *out, DWORD out_cch)
{
    HKEY hk;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return FALSE;

    DWORD type = 0, cb = out_cch * (DWORD)sizeof(wchar_t);
    LSTATUS rc = RegQueryValueExW(hk, value, NULL, &type, (LPBYTE)out, &cb);
    RegCloseKey(hk);

    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
        return FALSE;

    DWORD cch = cb / (DWORD)sizeof(wchar_t);
    if (cch == 0 || out[cch - 1] != L'\0')
        out[cch >= out_cch ? out_cch - 1 : cch] = L'\0';
    return TRUE;
}

static BOOL parse_hex64(const wchar_t *s, uint64_t *out)
{
    if (!s || !*s)
        return FALSE;
    uint64_t v = 0;
    for (int n = 0; *s && n < 16; ++s, ++n)
    {
        wchar_t c = *s;
        uint64_t d;
        if (c >= L'0' && c <= L'9')
            d = c - L'0';
        else if (c >= L'a' && c <= L'f')
            d = c - L'a' + 10;
        else if (c >= L'A' && c <= L'F')
            d = c - L'A' + 10;
        else
            return FALSE;
        v = (v << 4) | d;
    }
    *out = v;
    return TRUE;
}

static void hex_to_str(const BYTE *b, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i)
    {
        out[i * 2 + 0] = h[b[i] >> 4];
        out[i * 2 + 1] = h[b[i] & 0xf];
    }
    out[n * 2] = 0;
}

static void print_reg(const wchar_t *label, HKEY root, LPCWSTR sk, LPCWSTR vn)
{
    wchar_t buf[512];
    if (reg_read_sz(root, sk, vn, buf, ARRAYSIZE(buf)))
        wprintf(L"    %-28ls : %ls\n", label, buf);
    else
        wprintf(L"    %-28ls : <not readable>\n", label);
}

static void print_gdid(void)
{
    wprintf(L"[*] Passport Unique ID  (HKCU\\%ls\\LID)\n", IDCRL_EXTPROPS);

    wchar_t lid[64];
    if (!reg_read_sz(HKEY_CURRENT_USER, IDCRL_EXTPROPS, L"LID", lid, ARRAYSIZE(lid)))
    {
        wprintf(L"    [-] absent (wlidsvc has not provisioned this user)\n");
        return;
    }

    uint64_t puid;
    if (!parse_hex64(lid, &puid))
    {
        wprintf(L"    [-] LID present but not 16-hex: '%ls'\n", lid);
        return;
    }

    unsigned ns = (unsigned)(puid >> 48);
    const wchar_t *kind = ns == 0x0018   ? L"device PUID"
                          : ns == 0x0003 ? L"user PUID"
                                         : L"unknown class";

    wprintf(L"    LID (hex)            : %ls\n", lid);
    wprintf(L"    PUID (dec)           : %llu\n", (unsigned long long)puid);
    wprintf(L"    Namespace            : 0x%04X (%ls)\n", ns, kind);
    wprintf(L"    GDID                 : g:%llu\n", (unsigned long long)puid);
}

static void print_neighbours(void)
{
    wprintf(L"\n[*] Neighbouring identifiers\n");
    print_reg(L"MachineGuid", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    print_reg(L"SQM MachineId", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId");
    print_reg(L"IDCRL version", HKEY_LOCAL_MACHINE, IDCRL_ROOT, L"IDCRLVersion");
    print_reg(L"Login URL", HKEY_LOCAL_MACHINE, IDCRL_ROOT, L"LoginUrl");
    print_reg(L"Device DNS suffix", HKEY_LOCAL_MACHINE, IDCRL_ROOT, L"DeviceDNSSuffix");
}

static void enum_user_puids(void)
{
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IDCRL_NEGCACHE, 0,
                      KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return;

    wprintf(L"\n[*] User PUIDs  (HKLM\\%ls)\n", IDCRL_NEGCACHE);

    for (DWORD i = 0;; ++i)
    {
        wchar_t name[512];
        DWORD cch = ARRAYSIZE(name);
        LSTATUS rc = RegEnumKeyExW(hk, i, name, &cch, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS)
            break;

        const wchar_t *us = wcschr(name, L'_');
        if (!us || (us - name) != 16)
            continue;

        wchar_t hex[17];
        wmemcpy(hex, name, 16);
        hex[16] = L'\0';

        uint64_t p;
        if (!parse_hex64(hex, &p))
            continue;

        wprintf(L"    %ls  dec=%llu  sid=%ls\n",
                hex, (unsigned long long)p, us + 1);
    }
    RegCloseKey(hk);
}

#pragma pack(push, 1)
typedef struct
{
    BYTE Used20CallingMethod;
    BYTE MajorVersion;
    BYTE MinorVersion;
    BYTE DmiRevision;
    DWORD Length;
    BYTE SMBIOSTableData[1];
} RAW_SMBIOS_DATA;

typedef struct
{
    BYTE Type;
    BYTE Length;
    WORD Handle;
} SMBIOS_HEADER;

typedef struct
{
    SMBIOS_HEADER Hdr;
    BYTE Manufacturer;
    BYTE ProductName;
    BYTE Version;
    BYTE SerialNumber;
    BYTE Uuid[16];
    BYTE WakeUpType;
    BYTE SkuNumber;
    BYTE Family;
} SMBIOS_TYPE1;
#pragma pack(pop)

static const char *smbios_str(const BYTE *fmt_end, BYTE idx)
{
    if (idx == 0)
        return "";
    const char *p = (const char *)fmt_end;
    for (BYTE i = 1; i < idx; ++i)
    {
        while (*p)
            ++p;
        ++p;
        if (*p == '\0')
            return "";
    }
    return p;
}

static const BYTE *smbios_next(const SMBIOS_HEADER *s)
{
    const BYTE *p = (const BYTE *)s + s->Length;
    while (p[0] || p[1])
        ++p;
    return p + 2;
}

static void smbios_uuid_string(const BYTE u[16], char *out)
{
    sprintf(out,
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            u[3], u[2], u[1], u[0],
            u[5], u[4],
            u[7], u[6],
            u[8], u[9],
            u[10], u[11], u[12], u[13], u[14], u[15]);
}

static void print_smbios(void)
{
    wprintf(L"\n[*] SMBIOS  (GetSystemFirmwareTable 'RSMB')\n");

    DWORD cb = GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, NULL, 0);
    if (cb == 0)
    {
        wprintf(L"    [-] GetSystemFirmwareTable failed: %lu\n", GetLastError());
        return;
    }

    BYTE *buf = (BYTE *)LocalAlloc(LPTR, cb);
    if (!buf)
        return;

    if (GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, buf, cb) == 0)
    {
        wprintf(L"    [-] GetSystemFirmwareTable (2nd call) failed: %lu\n", GetLastError());
        LocalFree(buf);
        return;
    }

    RAW_SMBIOS_DATA *raw = (RAW_SMBIOS_DATA *)buf;
    wprintf(L"    SMBIOS version       : %u.%u\n",
            raw->MajorVersion, raw->MinorVersion);

    const BYTE *p = buf + offsetof(RAW_SMBIOS_DATA, SMBIOSTableData);
    const BYTE *end = buf + cb;

    while (p + sizeof(SMBIOS_HEADER) <= end)
    {
        const SMBIOS_HEADER *hdr = (const SMBIOS_HEADER *)p;
        if (hdr->Length < sizeof(SMBIOS_HEADER))
            break;

        if (hdr->Type == 1 && hdr->Length >= sizeof(SMBIOS_TYPE1))
        {
            const SMBIOS_TYPE1 *t1 = (const SMBIOS_TYPE1 *)hdr;
            const BYTE *strs = p + hdr->Length;
            char uuid[64];
            smbios_uuid_string(t1->Uuid, uuid);
            wprintf(L"    Manufacturer  (4097) : %hs\n", smbios_str(strs, t1->Manufacturer));
            wprintf(L"    Product       (4099) : %hs\n", smbios_str(strs, t1->ProductName));
            wprintf(L"    Version       (4100) : %hs\n", smbios_str(strs, t1->Version));
            wprintf(L"    Serial number (4101) : %hs\n", smbios_str(strs, t1->SerialNumber));
            wprintf(L"    UUID          (4102) : %hs\n", uuid);
            wprintf(L"    SKU                  : %hs\n", smbios_str(strs, t1->SkuNumber));
            wprintf(L"    Family               : %hs\n", smbios_str(strs, t1->Family));
        }

        if (hdr->Type == 127)
            break;
        p = smbios_next(hdr);
    }
    LocalFree(buf);
}

static BOOL sha256(const BYTE *in, DWORD cb_in, BYTE out[32])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOL ok = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return FALSE;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) < 0)
        goto done;
    if (BCryptHashData(hHash, (PUCHAR)in, cb_in, 0) < 0)
        goto done;
    if (BCryptFinishHash(hHash, out, 32, 0) < 0)
        goto done;
    ok = TRUE;

done:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static void print_tpm(void)
{
    wprintf(L"\n[*] TPM Endorsement Key  (Microsoft Platform Crypto Provider)\n");

    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS ss = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (ss != ERROR_SUCCESS)
    {
        wprintf(L"    [-] Platform Crypto Provider not available (0x%08X)\n", ss);
        return;
    }

    DWORD cb = 0;
    ss = NCryptGetProperty(hProv, NCRYPT_PCP_EKPUB_PROPERTY, NULL, 0, &cb, 0);
    if (ss != ERROR_SUCCESS || cb == 0)
    {
        wprintf(L"    [-] EKPub property not present (0x%08X)\n", ss);
        NCryptFreeObject(hProv);
        return;
    }

    BYTE *blob = (BYTE *)LocalAlloc(LPTR, cb);
    if (!blob)
    {
        NCryptFreeObject(hProv);
        return;
    }

    ss = NCryptGetProperty(hProv, NCRYPT_PCP_EKPUB_PROPERTY, blob, cb, &cb, 0);
    if (ss != ERROR_SUCCESS)
    {
        wprintf(L"    [-] NCryptGetProperty(EKPub) failed (0x%08X)\n", ss);
        LocalFree(blob);
        NCryptFreeObject(hProv);
        return;
    }

    BYTE digest[32];
    if (sha256(blob, cb, digest))
    {
        char hex[65];
        hex_to_str(digest, 32, hex);
        wprintf(L"    EKPub blob size      : %lu bytes\n", cb);
        wprintf(L"    EKPub SHA-256        : %hs\n", hex);
    }
    else
    {
        wprintf(L"    [-] SHA-256 hash failed\n");
    }

    LocalFree(blob);
    NCryptFreeObject(hProv);
}

static void print_disks(void)
{
    wprintf(L"\n[*] Physical disks  (IOCTL_STORAGE_QUERY_PROPERTY)\n");

    for (int idx = 0; idx < 32; ++idx)
    {
        wchar_t path[64];
        _snwprintf(path, ARRAYSIZE(path), L"\\\\.\\PhysicalDrive%d", idx);

        HANDLE h = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() == ERROR_FILE_NOT_FOUND)
                break;
            continue;
        }

        STORAGE_PROPERTY_QUERY q = {StorageDeviceProperty, PropertyStandardQuery, {0}};
        STORAGE_DESCRIPTOR_HEADER hdr = {0};
        DWORD n = 0;

        if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                             &q, sizeof(q), &hdr, sizeof(hdr), &n, NULL) ||
            hdr.Size < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            CloseHandle(h);
            continue;
        }

        BYTE *desc = (BYTE *)LocalAlloc(LPTR, hdr.Size);
        if (!desc)
        {
            CloseHandle(h);
            continue;
        }

        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                            &q, sizeof(q), desc, hdr.Size, &n, NULL))
        {
            STORAGE_DEVICE_DESCRIPTOR *d = (STORAGE_DEVICE_DESCRIPTOR *)desc;
            const char *serial = d->SerialNumberOffset ? (char *)desc + d->SerialNumberOffset : "";
            const char *vendor = d->VendorIdOffset ? (char *)desc + d->VendorIdOffset : "";
            const char *model = d->ProductIdOffset ? (char *)desc + d->ProductIdOffset : "";
            wprintf(L"    PhysicalDrive%d  serial=%hs  vendor=%hs  model=%hs\n",
                    idx, serial, vendor, model);
        }
        LocalFree(desc);
        CloseHandle(h);
    }
}

static const wchar_t *iftype_label(DWORD t)
{
    switch (t)
    {
    case IF_TYPE_ETHERNET_CSMACD:
        return L"eth";
    case IF_TYPE_IEEE80211:
        return L"wifi";
    case IF_TYPE_TUNNEL:
        return L"tun";
    case IF_TYPE_PPP:
        return L"ppp";
    case IF_TYPE_SOFTWARE_LOOPBACK:
        return L"lo";
    default:
        return L"other";
    }
}

static void print_macs(void)
{
    wprintf(L"\n[*] MAC addresses  (GetAdaptersAddresses)\n");

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG cb = 15 * 1024;
    IP_ADAPTER_ADDRESSES *buf = (IP_ADAPTER_ADDRESSES *)LocalAlloc(LPTR, cb);
    if (!buf)
        return;

    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, buf, &cb);
    if (rc == ERROR_BUFFER_OVERFLOW)
    {
        LocalFree(buf);
        buf = (IP_ADAPTER_ADDRESSES *)LocalAlloc(LPTR, cb);
        if (!buf)
            return;
        rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, buf, &cb);
    }
    if (rc != NO_ERROR)
    {
        wprintf(L"    [-] GetAdaptersAddresses failed: %lu\n", rc);
        LocalFree(buf);
        return;
    }

    for (IP_ADAPTER_ADDRESSES *a = buf; a; a = a->Next)
    {
        if (a->PhysicalAddressLength != 6)
            continue;
        if (a->IfType != IF_TYPE_ETHERNET_CSMACD &&
            a->IfType != IF_TYPE_IEEE80211)
            continue;
        const BYTE *m = a->PhysicalAddress;
        if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0)
            continue;
        wprintf(L"    %-5ls  %02X:%02X:%02X:%02X:%02X:%02X  %ls\n",
                iftype_label(a->IfType),
                m[0], m[1], m[2], m[3], m[4], m[5],
                a->FriendlyName ? a->FriendlyName : L"");
    }

    LocalFree(buf);
}

int main(void)
{
    _setmode(_fileno(stdout), _O_U8TEXT);

    wprintf(L"[+] Windows GDID + hardware descriptor report\n");
    wprintf(L"    wlidsvc.dll -> HKCU IdentityCRL\\ExtendedProperties\\LID\n");
    wprintf(L"    Hardware descriptors mirror wlidsvc's DeviceAddRequest payload.\n\n");

    print_gdid();
    print_neighbours();
    enum_user_puids();
    print_smbios();
    print_tpm();
    print_disks();
    print_macs();
    return 0;
}
