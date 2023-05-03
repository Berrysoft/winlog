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

pub const MSG_ERROR: u32 = 0xC0000001;
pub const MSG_WARNING: u32 = 0x80000002;
pub const MSG_INFO: u32 = 0x40000003;
pub const MSG_DEBUG: u32 = 0x40000004;
pub const MSG_TRACE: u32 = 0x40000005;

const REG_BASEKEY: &str = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Could not determine executable path")]
    ExePathNotFound,
    #[error("Call to RegisterEventSource failed")]
    RegisterSourceFailed,
    #[error("String convention failed")]
    StringConventionFailed,
}

#[cfg(not(feature = "env_logger"))]
pub struct Filter {}
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
use env_logger::filter::Filter;
#[cfg(feature = "env_logger")]
fn make_filter() -> Filter {
    use env_logger::filter::Builder;
    let mut builder = Builder::from_env("RUST_LOG");
    builder.build()
}

pub struct WinLogger {
    handle: HANDLE,
    filter: Filter,
}

unsafe impl Send for WinLogger {}
unsafe impl Sync for WinLogger {}

fn discard_result<R, E>(_result: &Result<R, E>) {}

pub fn deregister(name: &str) {
    discard_result(&try_deregister(name))
}

pub fn init(name: &str) -> Result<(), SetLoggerError> {
    log::set_boxed_logger(Box::new(WinLogger::new(name)))
        .map(|()| log::set_max_level(LevelFilter::Trace))
}

pub fn register(name: &str) {
    discard_result(&try_register(name))
}

pub fn try_deregister(name: &str) -> Result<(), Error> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey(REG_BASEKEY)?;
    cur_ver.delete_subkey(name).map_err(From::from)
}

pub fn try_register(name: &str) -> Result<(), Error> {
    let current_exe = ::std::env::current_exe()?;
    let exe_path = current_exe.to_str().ok_or(Error::ExePathNotFound)?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey(REG_BASEKEY)?;
    let (app_key, _) = cur_ver.create_subkey(name)?;
    app_key.set_value("EventMessageFile", &exe_path)?;
    app_key.set_value("TypesSupported", &7u32)?;
    Ok(())
}

impl WinLogger {
    pub fn new(name: &str) -> WinLogger {
        Self::try_new(name).unwrap_or(WinLogger {
            handle: 0,
            filter: make_filter(),
        })
    }

    pub fn try_new(name: &str) -> Result<WinLogger, Error> {
        let name = U16CString::from_str(name).map_err(|_| Error::StringConventionFailed)?;
        let handle = unsafe { RegisterEventSourceW(std::ptr::null_mut(), name.as_ptr()) };

        if handle == 0 {
            Err(Error::RegisterSourceFailed)
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
