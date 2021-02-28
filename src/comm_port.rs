use std::ptr::null_mut;
use winapi::{ctypes::c_void, shared::winerror::S_OK};
use winapi::um::{
	fltuser::{FilterConnectCommunicationPort, FilterSendMessage},
	handleapi::CloseHandle,
	winnt::{HANDLE, HRESULT}
};

use crate::win32_string;

pub struct CommunicationPort {
	handle: HANDLE
}

impl CommunicationPort {
	pub fn connect(port_name: &str) -> Result<Self, HRESULT> {
		let mut handle: HANDLE = null_mut();
		let r = unsafe {
			FilterConnectCommunicationPort(
				win32_string(port_name).as_ptr(),
				0,
				null_mut(),
				0,
				null_mut(),
				&mut handle
			)
		};
		if r != S_OK {
			Err(r)
		} else {
			Ok(CommunicationPort { handle })
		}
	}

	pub fn send_message(&self, in_buffer: &mut [u8], out_buffer: &mut[u8]) -> Result<u32, HRESULT> {
		let mut bytes_returned = 0;
		let r = unsafe {
			FilterSendMessage(
				self.handle,
				in_buffer.as_mut_ptr() as *mut c_void,
				in_buffer.len() as u32,
				out_buffer.as_mut_ptr() as *mut c_void,
				out_buffer.len() as u32,
				&mut bytes_returned
			)
		};
		if r != S_OK {
			Err(r)
		} else {
			Ok(bytes_returned)
		}
	}
}

impl Drop for CommunicationPort {
	fn drop(&mut self) {
		unsafe { CloseHandle(self.handle); }
	}
}
