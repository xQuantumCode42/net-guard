use netguard_control::{Request, Response, Status};
use netguard_core::{
    store::{Event, Store},
    *,
};
use netguard_platform::{ApplyReport, Backend};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
struct Runtime {
    store: Store,
    policy: Policy,
    backend: Option<Backend>,
    report: ApplyReport,
    error: Option<String>,
    active_ids: Vec<String>,
}
impl Runtime {
    fn status(&self) -> Status {
        Status {
            connected: true,
            active: self.backend.is_some(),
            version: env!("CARGO_PKG_VERSION").into(),
            platform: std::env::consts::OS.into(),
            report: self.report.clone(),
            capabilities: netguard_platform::capabilities(),
            error: self.error.clone(),
        }
    }
    fn resume(&mut self) -> Result<(), String> {
        let mut backend = Backend::new()?;
        self.report = backend.apply(&self.policy)?;
        self.backend = Some(backend);
        self.active_ids = self
            .policy
            .active_rules(now())
            .iter()
            .map(|r| r.id.clone())
            .collect();
        Ok(())
    }
    fn handle(&mut self, request: Request) -> Response {
        let result = match request {
            Request::Status => {
                return Response {
                    status: self.status(),
                    error: None,
                }
            }
            Request::Pause => {
                self.backend = None;
                self.report = ApplyReport::default();
                Ok(())
            }
            Request::Resume => {
                if self.backend.is_none() {
                    self.resume()
                } else {
                    Ok(())
                }
            }
            Request::Apply { policy } => (|| {
                policy.validate()?;
                let report = if let Some(backend) = self.backend.as_mut() {
                    backend.apply(&policy)?
                } else {
                    ApplyReport::default()
                };
                if let Err(e) = self.store.save_policy(&policy) {
                    if let Some(backend) = self.backend.as_mut() {
                        if backend.apply(&self.policy).is_err() {
                            self.backend = None;
                        }
                    }
                    return Err(e);
                }
                self.policy = policy;
                self.report = report;
                self.active_ids = self
                    .policy
                    .active_rules(now())
                    .iter()
                    .map(|r| r.id.clone())
                    .collect();
                Ok(())
            })(),
        };
        self.error = result.err();
        let _ = self.store.append_event(&Event {
            at: now(),
            kind: if self.error.is_some() {
                "error"
            } else {
                "control"
            }
            .into(),
            message: self.error.clone().unwrap_or_else(|| {
                format!(
                    "服務設定更新；防護 {}，原生規則 {}",
                    self.backend.is_some(),
                    self.report.applied
                )
            }),
        });
        Response {
            status: self.status(),
            error: self.error.clone(),
        }
    }
}
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("NetGuard {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|a| a == "--status") {
        println!(
            "{}",
            serde_json::to_string_pretty(&netguard_control::request(&Request::Status)?)
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if args.iter().any(|a| a == "--pause") {
        let r = netguard_control::request(&Request::Pause)?;
        if let Some(e) = r.error {
            return Err(e);
        }
        println!("Protection paused");
        return Ok(());
    }
    if args.iter().any(|a| a == "--observe") {
        println!(
            "{}",
            serde_json::to_string_pretty(&netguard_platform::observe()?)
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let option = |name: &str| args.windows(2).find(|p| p[0] == name).map(|p| p[1].clone());
    let path = PathBuf::from(option("--database").ok_or("Usage: netguard-agent --database <state.db> [--owner <SID/uid>] [--enable] | --observe | --version")?);
    let owner = option("--owner")
        .map(Ok)
        .unwrap_or_else(netguard_control::identity)?;
    let store = Store::open(&path)?;
    let policy = store.load_policy()?;
    let mut runtime = Runtime {
        store,
        policy,
        backend: None,
        report: ApplyReport::default(),
        error: None,
        active_ids: vec![],
    };
    if args.iter().any(|a| a == "--enable") {
        runtime.resume()?;
    }
    let runtime = Arc::new(Mutex::new(runtime));
    let shutdown = runtime.clone();
    ctrlc::set_handler(move || {
        if let Ok(mut r) = shutdown.lock() {
            r.backend = None;
        }
        std::process::exit(0);
    })
    .map_err(|e| e.to_string())?;
    let expiry = runtime.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let Ok(mut r) = expiry.lock() else {
            break;
        };
        if let Some(backend) = r.backend.as_mut() {
            if let Err(error) = backend.tick() {
                r.backend = None;
                r.report = ApplyReport::default();
                r.error = Some(format!("原生服務健康檢查失敗：{error}"));
            }
        }
        let ids: Vec<_> = r
            .policy
            .active_rules(now())
            .iter()
            .map(|r| r.id.clone())
            .collect();
        if r.backend.is_some() && ids != r.active_ids {
            let policy = r.policy.clone();
            match r.backend.as_mut().unwrap().apply(&policy) {
                Ok(report) => {
                    r.report = report;
                    r.active_ids = ids;
                }
                Err(error) => {
                    r.backend = None;
                    r.report = ApplyReport::default();
                    r.error = Some(format!("到期規則更新失敗，防護已停止：{error}"));
                }
            }
        }
    });
    println!("NetGuard 1.0.0 agent; owner={owner}; Ctrl+C to stop");
    netguard_control::serve(&owner, move |request| {
        runtime.lock().unwrap().handle(request)
    })
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
