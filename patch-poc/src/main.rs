// overwrites HKCU IdentityCRL\ExtendedProperties\LID.

#![cfg(windows)]
#![allow(non_snake_case)]

use std::env;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_EXPAND_SZ,
    REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

const IDCRL_EXTPROPS: &str = r"SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties";
const VALUE_NAME: &str = "LID";

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

fn read_lid() -> Option<String> {
    let sk = wide(IDCRL_EXTPROPS);
    let vn = wide(VALUE_NAME);

    let mut hk: HKEY = null_mut();
    if unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            sk.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut hk,
        )
    } != ERROR_SUCCESS
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

fn write_lid(new_value: &str) -> Result<(), u32> {
    let sk = wide(IDCRL_EXTPROPS);
    let vn = wide(VALUE_NAME);

    let mut hk: HKEY = null_mut();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            sk.as_ptr(),
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            &mut hk,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(rc as u32);
    }

    let value_w: Vec<u16> = OsString::from(new_value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let cb = (value_w.len() * 2) as u32;

    let rc = unsafe {
        RegSetValueExW(
            hk,
            vn.as_ptr(),
            0,
            REG_SZ,
            value_w.as_ptr() as *const u8,
            cb,
        )
    };
    unsafe {
        RegCloseKey(hk);
    }

    if rc != ERROR_SUCCESS {
        Err(rc as u32)
    } else {
        Ok(())
    }
}

fn validate(v: &str) -> Result<u64, String> {
    if v.len() != 16 {
        return Err(format!(
            "LID must be exactly 16 hex characters (got {})",
            v.len()
        ));
    }
    let n = u64::from_str_radix(v, 16).map_err(|_| format!("LID must be hex, got '{v}'"))?;
    let ns = (n >> 48) as u16;
    if ns != 0x0018 && ns != 0x0003 {
        return Err(format!(
            "namespace tag 0x{ns:04X} is not a valid PUID class (expected 0x0018 device or 0x0003 user)"
        ));
    }
    Ok(n)
}

fn print_usage() {
    eprintln!("usage: gdid-patch <new-LID-hex>");
    eprintln!();
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_usage();
        return ;
    }

    let new_hex = args[0].to_ascii_uppercase();
    let new_puid = match validate(&new_hex) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    match read_lid() {
        Some(prev) => {
            let prev_puid = u64::from_str_radix(&prev, 16).unwrap_or(0);
            println!("before: LID = {prev}  (GDID = g:{prev_puid})");
        }
        None => println!("before: LID absent (wlidsvc has not provisioned this user)"),
    }

    if let Err(rc) = write_lid(&new_hex) {
        eprintln!("write failed: rc = 0x{rc:08X}");
        return;
    }

    match read_lid() {
        Some(now) => println!("after : LID = {now}  (GDID = g:{new_puid})"),
        None => {
            eprintln!("after : LID missing after write (unexpected)");
            return;
        }
    }

    println!();
}
