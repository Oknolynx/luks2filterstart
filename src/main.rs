use luks2::{LuksDevice, LuksHeader};
use std::env::args;
use std::ffi::OsStr;
use std::io::{Seek, SeekFrom};
use std::iter::once;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::slice;
use winapi::{
    shared::minwindef::DWORD,
    um::{
        errhandlingapi::GetLastError,
        fileapi::{self as fs, OPEN_EXISTING},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        ioapiset::DeviceIoControl,
        winbase::FILE_FLAG_NO_BUFFERING,
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE},
    },
};
use windows_drives::BufferedHarddiskVolume;

const IOCTL_DISK_SET_LUKS2_INFO: DWORD = (7 << 16) | (2 << 14) | (0xc38 << 2) | 0;

#[allow(non_camel_case_types)]
#[repr(u32)]
enum EncryptionVariant {
    AES_128_XTS = 0,
    AES_256_XTS = 1,
}

#[repr(C)]
struct TargetVolume {
    sector_size: u16,
    first_segment_sector: u64,
    segment_length: u64,
    enc_variant: EncryptionVariant,
    key: [u8; 64],
}

fn main() -> Result<(), String> {
    if let Some(cmd) = args().nth(1) {
        match cmd.as_str() {
            "stop" => {
                let vol_nr = args()
                    .nth(2)
                    .expect("stop must be called with the volume number");
                let volume = open_handle(&format!("\\\\.\\HarddiskVolume{}", vol_nr))?;
                let res = send_message(volume, vec![0]);
                unsafe { CloseHandle(volume) };
                return res;
            }
            "nullcrypto" => {
                let vol_nr = args()
                    .nth(2)
                    .expect("nullcrypto must be called with the volume number");
                let volume = open_handle(&format!("\\\\.\\HarddiskVolume{}", vol_nr))?;
                let msg = create_message(512, 0, 0, &vec![0, 64]);
                let res = send_message(volume, msg);
                unsafe { CloseHandle(volume) };
                return res;
            }
            e => return Err(format!("'{}' is not a valid command", e)),
        }
    }

    let mut target_volume = find_luks_volume().unwrap();
    let volume = open_handle(&format!("\\\\.\\HarddiskVolume{}", target_volume.0))?;

    println!(
        "{}",
        format!(
            "found luks2 volume: \\\\.\\HarddiskVolume{}",
            target_volume.0
        )
    );
    // println!("key: {:x?}", target_volume.1.master_key());

    let sector_size = target_volume.1.sector_size as u16;
    let segment = &target_volume.1.active_segment;
    let segment_offset = segment.offset();
    let first_segment_sector = segment_offset / (segment.sector_size() as u64);
    let segment_length = target_volume.1.active_segment_size().unwrap();

    let msg = create_message(
        sector_size,
        first_segment_sector,
        segment_length,
        &target_volume.1.master_key(),
    );

    let res = send_message(volume, msg);

    unsafe { CloseHandle(volume) };

    res
}

fn find_luks_volume() -> Result<(u8, LuksDevice<BufferedHarddiskVolume>), String> {
    for i in 1..255 {
        if let Ok(mut volume) = BufferedHarddiskVolume::open(i) {
            if LuksHeader::read_from(&mut volume).is_ok() {
                volume
                    .seek(SeekFrom::Start(0))
                    .map_err(|e| format!("io error for volume {}: {}", i, e))?;

                /*
                println!("Enter password for luks partition:");
                let password = luks2::password::read()
                    .map_err(|e| format!("{}", e))?;
                */
                let password = "password";
                let sector_size = volume.geometry.bytes_per_sector as usize;
                return Ok((
                    i,
                    LuksDevice::from_device(volume, password.as_bytes(), sector_size).unwrap(),
                ));
            }
        }
    }
    Err("could not find a luks volume".to_string())
}

fn create_message(
    sector_size: u16,
    first_segment_sector: u64,
    segment_length: u64,
    key: &[u8],
) -> Vec<u8> {
    let mut nkey = [0u8; 64];
    if key.len() == 32 {
        nkey[..32].copy_from_slice(key);
    } else {
        nkey.copy_from_slice(key);
    }

    let vol = TargetVolume {
        sector_size,
        first_segment_sector,
        segment_length,
        enc_variant: if key.len() == 32 {
            EncryptionVariant::AES_128_XTS
        } else {
            EncryptionVariant::AES_256_XTS
        },
        key: nkey,
    };

    // get raw bytes of the TargelTolume struct
    let p = (&vol as *const TargetVolume) as *const u8;
    let msg = unsafe { slice::from_raw_parts(p, mem::size_of::<TargetVolume>()) }.to_vec();

    // add non-zero byte at front to indicate this is a LUKS2 volume
    once(1).chain(msg.into_iter()).collect()
}

fn send_message(handle: HANDLE, mut msg: Vec<u8>) -> Result<(), String> {
    let mut bytes_returned = 0u32;
    let r = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_SET_LUKS2_INFO,
            msg.as_mut_ptr() as _,
            msg.len() as u32,
            null_mut(),
            0,
            &mut bytes_returned,
            null_mut(),
        )
    };
    if r == 0 {
        Err(format!(
            "could not send message: error code {:#08x}",
            last_error()
        ))
    } else {
        Ok(())
    }
}

fn open_handle(path: &str) -> Result<HANDLE, String> {
    let path = win32_string(&path);
    let handle = unsafe {
        fs::CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = last_error();
        Err(match err {
            2 => "could not open handle because the device was not found".to_string(),
            5 => "could not open handle because access was denied - do you have administrator privileges?".to_string(),
            _ => format!("got invalid handle: error code {:#08x}", err)
        })
    } else {
        Ok(handle)
    }
}

// from https://drywa.me/2017/07/02/simple-win32-window-with-rust/
// Converts a string slice to a vector which can be interpreted as an LPCWSTR.
pub(crate) fn win32_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}
