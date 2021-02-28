mod comm_port;

use comm_port::CommunicationPort;
use luks2::{LuksHeader, LuksDevice};
use std::ffi::OsStr;
use std::io::{Seek, SeekFrom};
use std::iter::once;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::slice;
use windows_drives::BufferedHarddiskVolume;

const PORT_NAME: &'static str = "\\Luks2FilterPort";

#[allow(non_camel_case_types)]
#[repr(u32)]
enum EncryptionVariant {
    AES_128_XTS = 0,
    AES_256_XTS = 1
}

#[repr(C)]
struct TargetVolume {
    name: [u8; 32],
    first_segment_sector: u64,
    enc_variant: EncryptionVariant,
    key: [u8; 64]
}

fn main() -> Result<(), i32> {
    let target_volume = find_luks_volume().unwrap();
    let mut target_path = b"\\Device\\HarddiskVolume".to_vec();
    for c in format!("{}", target_volume.0).as_bytes() {
        target_path.push(*c);
    }
    target_path.resize_with(32, || 0);

    let segment = &target_volume.1.active_segment;
    let segment_offset = segment.offset();
    let first_segment_sector = segment_offset / (segment.sector_size() as u64);

    let port = CommunicationPort::connect(PORT_NAME)?;
    let mut msg = create_message(&target_path, first_segment_sector, &target_volume.1.master_key()).unwrap();
    let mut output = [];
    assert_eq!(0, port.send_message(&mut msg, &mut output)?);

    Ok(())
}

fn find_luks_volume() -> Result<(u8, LuksDevice<BufferedHarddiskVolume>), String> {
    for i in 1..255 {
        let mut volume = BufferedHarddiskVolume::open(i)?;
        if LuksHeader::read_from(&mut volume).is_ok() {
            volume.seek(SeekFrom::Start(0)).map_err(|e| format!("io error: {}", e))?;

            /*
            println!("Enter password for luks partition:");
            let password = luks2::password::read()
                .map_err(|e| format!("{}", e))?;
            */
            let password = "password";
            let sector_size = volume.geometry.bytes_per_sector as usize;
            return Ok((
                i,
                LuksDevice::from_device(
                    volume, password.as_bytes(), sector_size
                ).unwrap()
            ));
        }
    }
    Err("could not find a luks volume".to_string())
}

fn create_message(target_path: &[u8], first_segment_sector: u64, key: &[u8]) -> Result<Vec<u8>, String> {
    let mut nkey = [0u8; 64];
    if key.len() == 32 {
        nkey[..32].copy_from_slice(key);
    } else {
        nkey.copy_from_slice(key);
    }

    let mut name = [0u8; 32];
    name.copy_from_slice(target_path);

    let vol = TargetVolume {
        name,
        first_segment_sector,
        enc_variant: if key.len() == 32 { EncryptionVariant::AES_128_XTS } else { EncryptionVariant::AES_256_XTS },
        key: nkey
    };

    // get raw bytes of the TargelTolume struct
    let p = (&vol as *const TargetVolume) as *const u8;
    let msg: &[u8] = unsafe {
        slice::from_raw_parts(p, mem::size_of::<TargetVolume>())
    };
    Ok(msg.to_vec())
}

// from https://drywa.me/2017/07/02/simple-win32-window-with-rust/
// Converts a string slice to a vector which can be interpreted as an LPCWSTR.
pub(crate) fn win32_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}
