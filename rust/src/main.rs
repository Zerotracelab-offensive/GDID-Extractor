#![cfg(windows)]
#![allow(non_snake_case)]

use std::ffi::{CStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};

use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_BUFFER_OVERFLOW, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_SUCCESS, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, NCryptFreeObject, NCryptGetProperty,
    NCryptOpenStorageProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALGORITHM,
    NCRYPT_PROV_HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, IOCTL_STORAGE_QUERY_PROPERTY,
    STORAGE_DESCRIPTOR_HEADER, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
};
use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;
use windows_sys::Win32::System::IO::DeviceIoControl;

const IDCRL_EXTPROPS: &str = r"SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties";
const IDCRL_ROOT: &str = r"SOFTWARE\Microsoft\IdentityCRL";
const IDCRL_NEGCACHE: &str = r"SOFTWARE\Microsoft\IdentityCRL\NegativeCache";
const CRYPTO: &str = r"SOFTWARE\Microsoft\Cryptography";
const SQM: &str = r"SOFTWARE\Microsoft\SQMClient";

const SMBIOS_PROVIDER: u32 = 0x5253_4D42;

const PCP_EKPUB: [u16; 10] = [
    b'P' as u16,
    b'C' as u16,
    b'P' as u16,
    b'_' as u16,
    b'E' as u16,
    b'K' as u16,
    b'P' as u16,
    b'U' as u16,
    b'B' as u16,
    0,
];

const MSPCP: [u16; 35] = [
    b'M' as u16,
    b'i' as u16,
    b'c' as u16,
    b'r' as u16,
    b'o' as u16,
    b's' as u16,
    b'o' as u16,
    b'f' as u16,
    b't' as u16,
    b' ' as u16,
    b'P' as u16,
    b'l' as u16,
    b'a' as u16,
    b't' as u16,
    b'f' as u16,
    b'o' as u16,
    b'r' as u16,
    b'm' as u16,
    b' ' as u16,
    b'C' as u16,
    b'r' as u16,
    b'y' as u16,
    b'p' as u16,
    b't' as u16,
    b'o' as u16,
    b' ' as u16,
    b'P' as u16,
    b'r' as u16,
    b'o' as u16,
    b'v' as u16,
    b'i' as u16,
    b'd' as u16,
    b'e' as u16,
    b'r' as u16,
    0,
];

fn wide(s: &str) -> Vec<u16> {
    OsString::from(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .into_owned()
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn read_sz(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let sk = wide(subkey);
    let vn = wide(value);

    let mut hk: HKEY = null_mut();
    if unsafe { RegOpenKeyExW(root, sk.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut hk) }
        != ERROR_SUCCESS
    {
        return None;
    }

    let mut ty: REG_VALUE_TYPE = 0;
    let mut cb: u32 = 0;
    let rc = unsafe { RegQueryValueExW(hk, vn.as_ptr(), null_mut(), &mut ty, null_mut(), &mut cb) };
    if rc != ERROR_SUCCESS || (ty != REG_SZ && ty != REG_EXPAND_SZ) {
        unsafe {
            RegCloseKey(hk);
        }
        return None;
    }

    let mut buf: Vec<u16> = vec![0; (cb as usize).div_ceil(2).max(1)];
    let rc = unsafe {
        RegQueryValueExW(
            hk,
            vn.as_ptr(),
            null_mut(),
            &mut ty,
            buf.as_mut_ptr() as *mut u8,
            &mut cb,
        )
    };
    unsafe {
        RegCloseKey(hk);
    }

    if rc != ERROR_SUCCESS {
        None
    } else {
        Some(from_wide(&buf))
    }
}

fn enum_subkeys(root: HKEY, subkey: &str) -> Vec<String> {
    let mut out = Vec::new();
    let sk = wide(subkey);
    let mut hk: HKEY = null_mut();
    if unsafe { RegOpenKeyExW(root, sk.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut hk) }
        != ERROR_SUCCESS
    {
        return out;
    }

    let mut idx: u32 = 0;
    loop {
        let mut name = [0u16; 512];
        let mut cch: u32 = name.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                hk,
                idx,
                name.as_mut_ptr(),
                &mut cch,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        match rc {
            ERROR_SUCCESS => {
                out.push(from_wide(&name[..cch as usize]));
                idx += 1;
            }
            ERROR_MORE_DATA => {
                idx += 1;
            }
            ERROR_NO_MORE_ITEMS => break,
            _ => break,
        }
    }
    unsafe {
        RegCloseKey(hk);
    }
    out
}

fn parse_hex64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 16 {
        return None;
    }
    let mut v: u64 = 0;
    for c in s.chars() {
        v = (v << 4) | c.to_digit(16)? as u64;
    }
    Some(v)
}

fn print_reg(label: &str, root: HKEY, sk: &str, vn: &str) {
    let v = read_sz(root, sk, vn).unwrap_or_else(|| "<not readable>".into());
    println!("    {label:<28} : {v}");
}

fn print_gdid() {
    println!("[*] Passport Unique ID  (HKCU\\{IDCRL_EXTPROPS}\\LID)");

    let Some(lid) = read_sz(HKEY_CURRENT_USER, IDCRL_EXTPROPS, "LID") else {
        println!("    [-] absent (wlidsvc has not provisioned this user)");
        return;
    };

    let Some(puid) = parse_hex64(&lid) else {
        println!("    [-] LID present but not 16-hex: {lid}");
        return;
    };

    let ns = (puid >> 48) as u16;
    let kind = match ns {
        0x0018 => "device PUID",
        0x0003 => "user PUID",
        _ => "unknown class",
    };

    println!("    LID (hex)            : {lid}");
    println!("    PUID (dec)           : {puid}");
    println!("    Namespace            : 0x{ns:04X} ({kind})");
    println!("    GDID                 : g:{puid}");
}

fn print_neighbours() {
    println!("\n[*] Neighbouring identifiers");
    print_reg("MachineGuid", HKEY_LOCAL_MACHINE, CRYPTO, "MachineGuid");
    print_reg("SQM MachineId", HKEY_LOCAL_MACHINE, SQM, "MachineId");
    print_reg(
        "IDCRL version",
        HKEY_LOCAL_MACHINE,
        IDCRL_ROOT,
        "IDCRLVersion",
    );
    print_reg("Login URL", HKEY_LOCAL_MACHINE, IDCRL_ROOT, "LoginUrl");
    print_reg(
        "Device DNS suffix",
        HKEY_LOCAL_MACHINE,
        IDCRL_ROOT,
        "DeviceDNSSuffix",
    );
}

fn enum_user_puids() {
    let names = enum_subkeys(HKEY_LOCAL_MACHINE, IDCRL_NEGCACHE);
    if names.is_empty() {
        return;
    }

    println!("\n[*] User PUIDs  (HKLM\\{IDCRL_NEGCACHE})");
    for name in names {
        let Some((h, sid)) = name.split_once('_') else {
            continue;
        };
        if h.len() != 16 {
            continue;
        }
        let Some(p) = parse_hex64(h) else {
            continue;
        };
        println!("    {h}  dec={p}  sid={sid}");
    }
}

fn smbios_string(fmt_end: *const u8, idx: u8) -> String {
    if idx == 0 {
        return String::new();
    }
    unsafe {
        let mut p = fmt_end;
        for _ in 1..idx {
            while *p != 0 {
                p = p.add(1);
            }
            p = p.add(1);
            if *p == 0 {
                return String::new();
            }
        }
        CStr::from_ptr(p as *const i8)
            .to_string_lossy()
            .into_owned()
    }
}

fn smbios_uuid(u: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u[3], u[2], u[1], u[0],
        u[5], u[4],
        u[7], u[6],
        u[8], u[9],
        u[10], u[11], u[12], u[13], u[14], u[15]
    )
}

fn print_smbios() {
    println!("\n[*] SMBIOS  (GetSystemFirmwareTable 'RSMB')");

    let cb = unsafe { GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, null_mut(), 0) };
    if cb == 0 {
        println!("    [-] GetSystemFirmwareTable failed: {}", unsafe {
            GetLastError()
        });
        return;
    }

    let mut buf = vec![0u8; cb as usize];
    if unsafe { GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, buf.as_mut_ptr(), cb) } == 0 {
        println!(
            "    [-] GetSystemFirmwareTable (2nd call) failed: {}",
            unsafe { GetLastError() }
        );
        return;
    }

    // Header: Used20CallingMethod, Major, Minor, DmiRevision, Length(DWORD), TableData[]
    let major = buf[1];
    let minor = buf[2];
    println!("    SMBIOS version       : {major}.{minor}");

    let mut off = 8usize;
    while off + 4 <= buf.len() {
        let ty = buf[off];
        let len = buf[off + 1] as usize;
        if len < 4 {
            break;
        }

        if ty == 1 && len >= 27 {
            let manu = buf[off + 4];
            let product = buf[off + 5];
            let version = buf[off + 6];
            let serial = buf[off + 7];
            let uuid: [u8; 16] = buf[off + 8..off + 24].try_into().unwrap();
            let sku = buf[off + 25];
            let family = buf[off + 26];

            let strs = unsafe { buf.as_ptr().add(off + len) };
            println!("    Manufacturer  (4097) : {}", smbios_string(strs, manu));
            println!(
                "    Product       (4099) : {}",
                smbios_string(strs, product)
            );
            println!(
                "    Version       (4100) : {}",
                smbios_string(strs, version)
            );
            println!("    Serial number (4101) : {}", smbios_string(strs, serial));
            println!("    UUID          (4102) : {}", smbios_uuid(&uuid));
            println!("    SKU                  : {}", smbios_string(strs, sku));
            println!("    Family               : {}", smbios_string(strs, family));
        }

        if ty == 127 {
            break;
        }

        let mut p = off + len;
        while p + 1 < buf.len() && (buf[p] != 0 || buf[p + 1] != 0) {
            p += 1;
        }
        off = p + 2;
    }
}

fn sha256(input: &[u8]) -> Option<[u8; 32]> {
    let mut h_alg: BCRYPT_ALG_HANDLE = null_mut();
    let mut h_hash: BCRYPT_HASH_HANDLE = null_mut();

    if unsafe { BCryptOpenAlgorithmProvider(&mut h_alg, BCRYPT_SHA256_ALGORITHM, null(), 0) } < 0 {
        return None;
    }
    if unsafe { BCryptCreateHash(h_alg, &mut h_hash, null_mut(), 0, null(), 0, 0) } < 0 {
        unsafe {
            BCryptCloseAlgorithmProvider(h_alg, 0);
        }
        return None;
    }
    let mut out = [0u8; 32];
    let ok = unsafe {
        BCryptHashData(h_hash, input.as_ptr(), input.len() as u32, 0) >= 0
            && BCryptFinishHash(h_hash, out.as_mut_ptr(), out.len() as u32, 0) >= 0
    };
    unsafe {
        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);
    }
    if ok {
        Some(out)
    } else {
        None
    }
}

fn print_tpm() {
    println!("\n[*] TPM Endorsement Key  (Microsoft Platform Crypto Provider)");

    let mut h_prov: NCRYPT_PROV_HANDLE = 0;
    let ss = unsafe { NCryptOpenStorageProvider(&mut h_prov, MSPCP.as_ptr() as PCWSTR, 0) };
    if ss != 0 {
        println!(
            "    [-] Platform Crypto Provider not available (0x{:08X})",
            ss as u32
        );
        return;
    }

    let mut cb: u32 = 0;
    let ss = unsafe {
        NCryptGetProperty(
            h_prov,
            PCP_EKPUB.as_ptr() as PCWSTR,
            null_mut(),
            0,
            &mut cb,
            0,
        )
    };
    if ss != 0 || cb == 0 {
        println!("    [-] EKPub property not present (0x{:08X})", ss as u32);
        unsafe {
            NCryptFreeObject(h_prov);
        }
        return;
    }

    let mut blob = vec![0u8; cb as usize];
    let ss = unsafe {
        NCryptGetProperty(
            h_prov,
            PCP_EKPUB.as_ptr() as PCWSTR,
            blob.as_mut_ptr(),
            cb,
            &mut cb,
            0,
        )
    };
    unsafe {
        NCryptFreeObject(h_prov);
    }

    if ss != 0 {
        println!(
            "    [-] NCryptGetProperty(EKPub) failed (0x{:08X})",
            ss as u32
        );
        return;
    }

    match sha256(&blob[..cb as usize]) {
        Some(d) => {
            println!("    EKPub blob size      : {} bytes", cb);
            println!("    EKPub SHA-256        : {}", hex(&d));
        }
        None => println!("    [-] SHA-256 failed"),
    }
}

fn print_disks() {
    println!("\n[*] Physical disks  (IOCTL_STORAGE_QUERY_PROPERTY)");

    for idx in 0..32 {
        let path = wide(&format!(r"\\.\PhysicalDrive{idx}"));
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            if unsafe { GetLastError() } == 2 {
                break;
            } // ERROR_FILE_NOT_FOUND
            continue;
        }

        let q = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut hdr = STORAGE_DESCRIPTOR_HEADER {
            Version: 0,
            Size: 0,
        };
        let mut n: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &q as *const _ as *const _,
                std::mem::size_of_val(&q) as u32,
                &mut hdr as *mut _ as *mut _,
                std::mem::size_of_val(&hdr) as u32,
                &mut n,
                null_mut(),
            )
        };
        if ok == 0 || (hdr.Size as usize) < std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            unsafe {
                CloseHandle(h);
            }
            continue;
        }

        let mut buf = vec![0u8; hdr.Size as usize];
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &q as *const _ as *const _,
                std::mem::size_of_val(&q) as u32,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut n,
                null_mut(),
            )
        };
        unsafe {
            CloseHandle(h);
        }
        if ok == 0 {
            continue;
        }

        let d: &STORAGE_DEVICE_DESCRIPTOR = unsafe { &*(buf.as_ptr() as *const _) };
        let read = |off: u32| -> String {
            if off == 0 {
                return String::new();
            }
            let p = unsafe { buf.as_ptr().add(off as usize) as *const i8 };
            unsafe { CStr::from_ptr(p).to_string_lossy().trim().to_owned() }
        };
        println!(
            "    PhysicalDrive{idx}  serial={}  vendor={}  model={}",
            read(d.SerialNumberOffset),
            read(d.VendorIdOffset),
            read(d.ProductIdOffset)
        );
    }
}

fn iftype_label(t: u32) -> &'static str {
    match t {
        IF_TYPE_ETHERNET_CSMACD => "eth",
        IF_TYPE_IEEE80211 => "wifi",
        _ => "other",
    }
}

fn print_macs() {
    println!("\n[*] MAC addresses  (GetAdaptersAddresses)");

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut cb: u32 = 15 * 1024;
    let mut buf = vec![0u8; cb as usize];

    let mut rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut cb,
        )
    };
    if rc == ERROR_BUFFER_OVERFLOW {
        buf = vec![0u8; cb as usize];
        rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                null_mut(),
                buf.as_mut_ptr() as *mut _,
                &mut cb,
            )
        };
    }
    if rc != NO_ERROR {
        println!("    [-] GetAdaptersAddresses failed: {rc}");
        return;
    }

    let mut a = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !a.is_null() {
        let ad = unsafe { &*a };
        if ad.PhysicalAddressLength == 6
            && (ad.IfType == IF_TYPE_ETHERNET_CSMACD || ad.IfType == IF_TYPE_IEEE80211)
        {
            let m = &ad.PhysicalAddress[..6];
            if m.iter().any(|&b| b != 0) {
                let name = unsafe {
                    let p = ad.FriendlyName;
                    if p.is_null() {
                        String::new()
                    } else {
                        let mut n = 0;
                        while *p.add(n) != 0 {
                            n += 1;
                        }
                        from_wide(std::slice::from_raw_parts(p, n))
                    }
                };
                println!(
                    "    {:<5}  {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}  {}",
                    iftype_label(ad.IfType),
                    m[0],
                    m[1],
                    m[2],
                    m[3],
                    m[4],
                    m[5],
                    name
                );
            }
        }
        a = ad.Next;
    }
}

fn main() {
    println!("[+] Windows GDID + hardware descriptor report");

    print_gdid();
    print_neighbours();
    enum_user_puids();
    print_smbios();
    print_tpm();
    print_disks();
    print_macs();
}
