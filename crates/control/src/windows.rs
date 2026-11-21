use super::*;
use std::{
    fs::{File, OpenOptions},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*},
};
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn identity() -> Result<String, String> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut size = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), size, &mut size);
        CloseHandle(token);
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        let mut sid = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut len = 0;
        while *sid.add(len) != 0 {
            len += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid, len));
        LocalFree(sid.cast());
        Ok(value)
    }
}
struct TimedPipe {
    file: File,
    deadline: Instant,
}
impl Read for TimedPipe {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut received = 0;
            let length = out.len().min(u32::MAX as usize) as u32;
            // Preserve ERROR_NO_DATA from a nonblocking pipe as "try again".
            if unsafe {
                ReadFile(
                    self.file.as_raw_handle(),
                    out.as_mut_ptr(),
                    length,
                    &mut received,
                    null_mut(),
                )
            } != 0
            {
                return Ok(received as usize);
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == ERROR_NO_DATA as i32 => {
                    if Instant::now() > self.deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "IPC read timeout",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Some(code) if code == ERROR_BROKEN_PIPE as i32 => return Ok(0),
                _ => return Err(error),
            }
        }
    }
}
impl Write for TimedPipe {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        loop {
            match self.file.write(data) {
                Ok(0) => {
                    if Instant::now() > self.deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "IPC write timeout",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                r => return r,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub fn request(command: &Request) -> Result<Response, String> {
    let name = format!(r"\\.\pipe\netguard-{}", identity()?);
    request_on_pipe(&name, command)
}

fn request_on_pipe(name: &str, command: &Request) -> Result<Response, String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let file = loop {
        match OpenOptions::new().read(true).write(true).open(name) {
            Ok(f) => break f,
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(e) => return Err(format!("防護服務未連線：{e}")),
        }
    };
    let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
    if unsafe { SetNamedPipeHandleState(file.as_raw_handle(), &mode, null(), null()) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut stream = TimedPipe {
        file,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    write_message(&mut stream, command)?;
    let response = read_message(&mut stream).map_err(|e| format!("無法讀取服務回應：{e}"))?;
    stream.write_all(&[1]).map_err(|e| e.to_string())?;
    Ok(response)
}
pub fn serve(
    owner: &str,
    handler: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> Result<(), String> {
    if !owner.starts_with("S-1-")
        || !owner
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
    {
        return Err("無效 owner SID".into());
    }
    let name = wide(&format!(r"\\.\pipe\netguard-{owner}"));
    let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner})"));
    let file = {
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &attributes,
            )
        };
        unsafe {
            LocalFree(descriptor);
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "無法建立專用通訊端點（可能已有服務）：{}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe { File::from_raw_handle(handle) }
    };
    loop {
        handle_client(&file, &handler)?;
    }
}

fn handle_client(file: &File, handler: &impl Fn(Request) -> Response) -> Result<(), String> {
    let handle = file.as_raw_handle();
    loop {
        // In PIPE_NOWAIT a successful call may only arm the listener.
        if unsafe { ConnectNamedPipe(handle, null_mut()) } == 0 {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => break,
                ERROR_NO_DATA => disconnect_client(handle)?,
                ERROR_PIPE_LISTENING => {}
                error => return Err(format!("IPC connect error {error}")),
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stream = TimedPipe {
        file: file.try_clone().map_err(|e| e.to_string())?,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    if let Ok(command) = read_message(&mut stream) {
        let response = handler(command);
        let _ = write_message(&mut stream, &response);
        // Client acknowledges consumption, so closing cannot discard an unread response.
        let mut ack = [0];
        let _ = stream.read(&mut ack);
    }
    disconnect_client(handle)
}

fn disconnect_client(handle: HANDLE) -> Result<(), String> {
    if unsafe { DisconnectNamedPipe(handle) } != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED as i32) {
        Ok(())
    } else {
        Err(format!("IPC disconnect error: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_requests_after_client_leaves_before_server_reads() {
        let name = format!(r"\\.\pipe\netguard-test-{}", std::process::id());
        let wide_name = wide(&name);
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                null(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let server = unsafe { File::from_raw_handle(handle) };
        let abandoned = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap();
        drop(abandoned);
        let (done, finished) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let handler = |request| {
                assert!(matches!(request, Request::Status));
                let mut status = Status::offline("test fixture");
                status.connected = true;
                Response {
                    status,
                    error: None,
                }
            };
            let result =
                handle_client(&server, &handler).and_then(|_| handle_client(&server, &handler));
            done.send(result).unwrap();
        });
        for _ in 0..2 {
            let response = request_on_pipe(&name, &Request::Status)
                .expect("pipe must recover after abandoned connection");
            assert!(response.status.connected);
        }
        finished
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
    }
}
