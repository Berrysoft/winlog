//! A simple [Rust log](https://docs.rs/log/latest/log/) backend
//! to send messages to [Windows event log](https://docs.microsoft.com/en-us/windows/desktop/eventlog/event-logging).

#![warn(missing_docs)]

use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use widestring::U16CString;
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
        EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    },
};
use winreg::{enums::*, RegKey};

// Generated from MC.
const MSG_ERROR: u32 = 0xC0000001;
const MSG_WARNING: u32 = 0x80000002;
const MSG_INFO: u32 = 0x40000003;
const MSG_DEBUG: u32 = 0x40000004;
const MSG_TRACE: u32 = 0x40000005;

const REG_BASEKEY: &str = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application";

/// Error type of methods in this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// System error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// String convertion error.
    #[error("String convertion failed")]
    StringConvertionFailed,
    /// Calling [`log::set_boxed_logger`] failed.
    #[error("Set logger failed: {0}")]
    SetLoggerFailed(#[from] SetLoggerError),
}

#[cfg(not(feature = "env_logger"))]
struct Filter {}
#[cfg(not(feature = "env_logger"))]
impl Filter {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn matches(&self, _record: &Record) -> bool {
        true
    }
}
#[cfg(not(feature = "env_logger"))]
fn make_filter() -> Filter {
    Filter {}
}

#[cfg(feature = "env_logger")]
use env_logger::Logger as Filter;
#[cfg(feature = "env_logger")]
fn make_filter() -> Filter {
    use env_logger::Builder;
    let mut builder = Builder::from_env("RUST_LOG");
    builder.build()
}

struct WinLogger {
    handle: HANDLE,
    filter: Filter,
}

/// Initialize the global logger as the windows event logger.
/// See document of [`register`].
pub fn init(name: &str) -> Result<(), Error> {
    log::set_boxed_logger(Box::new(WinLogger::new(name)?))?;
    log::set_max_level(LevelFilter::Trace);
    Ok(())
}

/// Attempt to remove the event source registry.
/// See document of [`register`].
pub fn deregister(name: &str) -> Result<(), Error> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey(REG_BASEKEY)?;
    cur_ver.delete_subkey(name).map_err(From::from)
}

/// Attempt to add the event source registry.
///
/// Any event source sould be registried first.
/// You need to call [`register`] when installing the program,
/// and call [`deregister`] when uninstalling the program.
pub fn register(name: &str) -> Result<(), Error> {
    let current_exe = ::std::env::current_exe()?;
    let exe_path = current_exe.to_str().ok_or(Error::StringConvertionFailed)?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey(REG_BASEKEY)?;
    let (app_key, _) = cur_ver.create_subkey(name)?;
    app_key.set_value("EventMessageFile", &exe_path)?;
    app_key.set_value("TypesSupported", &7u32)?;
    Ok(())
}

impl WinLogger {
    pub fn new(name: &str) -> Result<WinLogger, Error> {
        let name = U16CString::from_str(name).map_err(|_| Error::StringConvertionFailed)?;
        let handle = unsafe { RegisterEventSourceW(std::ptr::null_mut(), name.as_ptr()) };

        if handle.is_null() {
            Err(Error::Io(std::io::Error::last_os_error()))
        } else {
            Ok(WinLogger {
                handle,
                filter: make_filter(),
            })
        }
    }
}

impl Drop for WinLogger {
    fn drop(&mut self) {
        unsafe { DeregisterEventSource(self.handle) };
    }
}

// SAFETY: event source should be thread safe
unsafe impl Send for WinLogger {}
unsafe impl Sync for WinLogger {}

impl log::Log for WinLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if self.filter.matches(record) {
            let level = record.level();
            let (wtype, dweventid) = match level {
                Level::Error => (EVENTLOG_ERROR_TYPE, MSG_ERROR),
                Level::Warn => (EVENTLOG_WARNING_TYPE, MSG_WARNING),
                Level::Info => (EVENTLOG_INFORMATION_TYPE, MSG_INFO),
                Level::Debug => (EVENTLOG_INFORMATION_TYPE, MSG_DEBUG),
                Level::Trace => (EVENTLOG_INFORMATION_TYPE, MSG_TRACE),
            };

            let msg = U16CString::from_str_truncate(format!("{}", record.args()));
            let msg_ptr = msg.as_ptr();

            unsafe {
                ReportEventW(
                    self.handle,
                    wtype,     // type
                    0,         // category
                    dweventid, // event id == resource msg id
                    std::ptr::null_mut(),
                    1,
                    0,
                    &msg_ptr,
                    std::ptr::null_mut(),
                )
            };
        }
    }

    fn flush(&self) {}
}
