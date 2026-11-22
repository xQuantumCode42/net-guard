#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use netguard_control::{Request, Status};
use netguard_core::{
    store::{Event, Store},
    *,
};
use serde::Serialize;
use std::path::PathBuf;
use tauri::{Manager, State};
use tauri_plugin_autostart::ManagerExt;

struct AppState {
    path: PathBuf,
}
#[derive(Serialize)]
struct Snapshot {
    status: Status,
    policy: Policy,
    flows: Vec<Flow>,
    events: Vec<Event>,
    observation_error: Option<String>,
    data_dir: String,
}
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}
#[cfg(not(target_os = "linux"))]
fn service_status() -> Status {
    netguard_control::request(&Request::Status)
        .map(|r| r.status)
        .unwrap_or_else(Status::offline)
}
fn load_policy(store: &Store) -> Result<Policy, String> {
    #[cfg(target_os = "linux")]
    {
        let _ = store;
        netguard_control::request(&Request::GetPolicy)?
            .policy
            .ok_or("背景服務未提供規則，請確認服務版本".into())
    }
    #[cfg(not(target_os = "linux"))]
    store.load_policy()
}
fn save(path: PathBuf, policy: Policy) -> Result<Status, String> {
    policy.validate()?;
    let store = Store::open(&path)?;
    let status = match netguard_control::request(&Request::Apply {
        policy: policy.clone(),
    }) {
        Ok(response) => {
            if let Some(error) = response.error {
                return Err(error);
            }
            response.status
        }
        Err(error) => {
            #[cfg(target_os = "linux")]
            return Err(error);
            #[cfg(not(target_os = "linux"))]
            {
                store.save_policy(&policy)?;
                Status::offline(format!("已儲存本機規則，服務啟動前不會生效。{error}"))
            }
        }
    };
    // Agent and UI share the same selected DB. Only the agent writes when connected.
    store.append_event(&Event {
        at: now(),
        kind: "policy".into(),
        message: format!(
            "儲存 {} 條規則；原生生效 {} 條",
            policy.rules.len(),
            status.report.applied
        ),
    })?;
    Ok(status)
}
#[tauri::command]
async fn get_snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    let path = state.path.clone();
    blocking(move || {
        let store = Store::open(&path)?;
        #[cfg(target_os = "linux")]
        let (status, policy) = match netguard_control::request(&Request::GetPolicy) {
            Ok(response) => (
                response.status,
                response.policy.ok_or("背景服務未提供規則")?,
            ),
            Err(error) => (Status::offline(error), Policy::default()),
        };
        #[cfg(not(target_os = "linux"))]
        let (status, policy) = (service_status(), load_policy(&store)?);
        let (flows, observation_error) = match netguard_platform::observe() {
            Ok(f) => (f, None),
            Err(e) => (vec![], Some(e)),
        };
        Ok(Snapshot {
            status,
            policy,
            flows,
            events: store.events(100)?,
            observation_error,
            data_dir: path.display().to_string(),
        })
    })
    .await
}
#[tauri::command]
async fn save_policy(state: State<'_, AppState>, policy: Policy) -> Result<Status, String> {
    let path = state.path.clone();
    blocking(move || save(path, policy)).await
}
#[tauri::command]
async fn agent_control(action: String) -> Result<Status, String> {
    blocking(move || {
        let request = match action.as_str() {
            "pause" => Request::Pause,
            "resume" => Request::Resume,
            _ => return Err("未知操作".into()),
        };
        let response = netguard_control::request(&request)?;
        if let Some(e) = response.error {
            return Err(e);
        }
        Ok(response.status)
    })
    .await
}
#[tauri::command]
async fn import_policy(state: State<'_, AppState>, text: String) -> Result<Status, String> {
    let path = state.path.clone();
    blocking(move || {
        if text.len() > 8 * 1024 * 1024 {
            return Err("匯入資料超過 8 MB".into());
        }
        let export: netguard_core::store::Export =
            serde_json::from_str(&text).map_err(|e| e.to_string())?;
        if export.schema_version != 1 {
            return Err("不支援的設定格式版本".into());
        }
        save(path, export.policy)
    })
    .await
}
fn merge_feed(path: PathBuf, text: String) -> Result<Status, String> {
    let mut rules = netguard_core::feed::parse_drop(&text)?;
    for rule in &mut rules {
        rule.expires_at = Some(now() + 48 * 3600);
    }
    let mut policy = load_policy(&Store::open(&path)?)?;
    policy
        .rules
        .retain(|r| r.source.as_deref() != Some("spamhaus_drop"));
    policy.rules.extend(rules);
    save(path, policy)
}
#[tauri::command]
async fn import_feed(state: State<'_, AppState>, text: String) -> Result<Status, String> {
    let path = state.path.clone();
    blocking(move || merge_feed(path, text)).await
}
#[tauri::command]
async fn update_feed(state: State<'_, AppState>) -> Result<Status, String> {
    let path = state.path.clone();
    blocking(move || {
        use std::io::Read;
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("NetGuard/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        let mut text = String::new();
        for url in [
            "https://www.spamhaus.org/drop/drop_v4.json",
            "https://www.spamhaus.org/drop/drop_v6.json",
        ] {
            let response = client
                .get(url)
                .send()
                .and_then(|r| r.error_for_status())
                .map_err(|e| e.to_string())?;
            let mut body = String::new();
            response
                .take(4 * 1024 * 1024 + 1)
                .read_to_string(&mut body)
                .map_err(|e| e.to_string())?;
            if body.len() > 4 * 1024 * 1024 {
                return Err("來源資料超過大小限制".into());
            }
            netguard_core::feed::parse_drop(&body)?;
            text.push_str(&body);
            text.push('\n');
        }
        merge_feed(path, text)
    })
    .await
}
#[tauri::command]
async fn export_policy(state: State<'_, AppState>) -> Result<String, String> {
    let path = state.path.clone();
    blocking(move || {
        let policy = load_policy(&Store::open(&path)?)?;
        serde_json::to_string_pretty(&netguard_core::store::Export {
            schema_version: 1,
            policy,
        })
        .map_err(|e| e.to_string())
    })
    .await
}
#[tauri::command]
async fn clear_events(state: State<'_, AppState>) -> Result<(), String> {
    let path = state.path.clone();
    blocking(move || Store::open(&path)?.clear_events()).await
}
#[tauri::command]
fn autostart_enabled(app: tauri::AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}
#[tauri::command]
fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if enabled {
        app.autolaunch().enable()
    } else {
        app.autolaunch().disable()
    }
    .map_err(|e| e.to_string())
}
#[tauri::command]
async fn launch_agent(state: State<'_, AppState>) -> Result<Status, String> {
    let path = state.path.clone();
    blocking(move || start_protection(path)).await
}

fn start_protection(path: PathBuf) -> Result<Status, String> {
    if let Ok(response) = netguard_control::request(&Request::Status) {
        return enable_protection(response.status);
    }
    #[cfg(windows)]
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let agent = exe
        .parent()
        .ok_or("找不到執行檔目錄")?
        .join(if cfg!(windows) {
            "netguard-agent.exe"
        } else {
            "netguard-agent"
        });
    #[cfg(windows)]
    if !agent.is_file() {
        return Err(
            "找不到 netguard-agent；請將服務執行檔放在桌面程式旁，或依 README 手動啟動".into(),
        );
    }
    let owner = netguard_control::identity()?;
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::{
            Foundation::{ERROR_CANCELLED, WAIT_OBJECT_0},
            System::Threading::{GetExitCodeProcess, WaitForSingleObject},
            UI::{Shell::*, WindowsAndMessaging::SW_HIDE},
        };
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let verb = wide("runas");
        let executable = wide(&agent.display().to_string());
        let arguments = wide(&format!(
            "--database \"{}\" --owner {owner}",
            path.display()
        ));
        let mut launch = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
            lpVerb: verb.as_ptr(),
            lpFile: executable.as_ptr(),
            lpParameters: arguments.as_ptr(),
            nShow: SW_HIDE,
            ..Default::default()
        };
        if unsafe { ShellExecuteExW(&mut launch) } == 0 {
            let error = std::io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                "已取消 Windows 管理員授權".into()
            } else {
                format!("無法啟動防護服務：{error}")
            });
        }
        let process = (!launch.hProcess.is_null())
            .then(|| unsafe { OwnedHandle::from_raw_handle(launch.hProcess) });
        wait_for_protection(|| {
            let handle = process.as_ref()?.as_raw_handle();
            if unsafe { WaitForSingleObject(handle, 0) } != WAIT_OBJECT_0 {
                return None;
            }
            let mut code = 0;
            if unsafe { GetExitCodeProcess(handle, &mut code) } != 0 {
                Some(format!("背景程序已結束（代碼 {code}）"))
            } else {
                Some("背景程序已結束".into())
            }
        })
    }
    #[cfg(target_os = "linux")]
    {
        let _ = path;
        let unit = format!("netguard@{owner}.service");
        let exit = std::process::Command::new("/usr/bin/pkexec")
            .args(["/usr/bin/systemctl", "start", &unit])
            .status()
            .map_err(|e| format!("無法開啟系統授權：{e}"))?;
        if !exit.success() {
            return Err(format!(
                "無法啟動 {unit}（{exit}）。可用 journalctl -u {unit} 查看原因。"
            ));
        }
        wait_for_protection(|| None)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (owner, path);
        Err("macOS 需先完成 System Extension 簽章與啟用".into())
    }
}

fn enable_protection(status: Status) -> Result<Status, String> {
    if status.connected && status.active {
        return Ok(status);
    }
    let response = netguard_control::request(&Request::Resume)?;
    if let Some(error) = response.error.or(response.status.error.clone()) {
        return Err(error);
    }
    if !response.status.connected || !response.status.active {
        return Err("服務已連線，但未確認防護啟用".into());
    }
    Ok(response.status)
}

#[cfg(any(windows, target_os = "linux"))]
fn wait_for_protection(mut child_exit: impl FnMut() -> Option<String>) -> Result<Status, String> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let error = match netguard_control::request(&Request::Status) {
            Ok(response) => return enable_protection(response.status),
            Err(error) => error,
        };
        if let Some(exit) = child_exit() {
            return Err(format!("{exit}。{error}"));
        }
        if Instant::now() >= deadline {
            return Err(format!("等待防護服務回應逾時。{error}"));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            let path = app.path().app_data_dir()?.join("state.db");
            Store::open(&path).map_err(std::io::Error::other)?;
            app.manage(AppState { path });
            use tauri::{
                menu::{Menu, MenuItem},
                tray::TrayIconBuilder,
            };
            let show = MenuItem::with_id(app, "show", "開啟 NetGuard", true, None::<&str>)?;
            let quit =
                MenuItem::with_id(app, "quit", "結束介面（服務繼續運作）", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip(concat!("NetGuard ", env!("CARGO_PKG_VERSION")))
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            save_policy,
            agent_control,
            import_policy,
            import_feed,
            update_feed,
            export_policy,
            clear_events,
            set_autostart,
            autostart_enabled,
            launch_agent
        ])
        .run(tauri::generate_context!())
        .expect("NetGuard desktop startup failed");
}
