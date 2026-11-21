use super::*;
use std::{
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    time::Duration,
};
pub fn identity() -> Result<String, String> {
    Ok(unsafe { libc::getuid() }.to_string())
}
fn socket(owner: &str) -> Result<PathBuf, String> {
    owner.parse::<u32>().map_err(|_| "無效 uid")?;
    Ok(PathBuf::from(format!("/run/netguard/{owner}.sock")))
}
pub fn request(command: &Request) -> Result<Response, String> {
    let mut stream =
        UnixStream::connect(socket(&identity()?)?).map_err(|e| format!("防護服務未連線：{e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    write_message(&mut stream, command)?;
    read_message(&mut stream)
}
pub fn serve(
    owner: &str,
    handler: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("服務需要 root 權限".into());
    }
    let path = socket(owner)?;
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() || meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
        return Err("不安全的服務 socket 目錄".into());
    }
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            return Err("已有服務執行中".into());
        }
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let cpath =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    if unsafe { libc::chown(cpath.as_ptr(), owner.parse().unwrap(), u32::MAX) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    for connection in listener.incoming() {
        let mut stream = connection.map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        if let Ok(command) = read_message(&mut stream) {
            let _ = write_message(&mut stream, &handler(command));
        }
    }
    Ok(())
}
