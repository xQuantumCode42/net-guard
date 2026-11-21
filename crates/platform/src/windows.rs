use super::*;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::{null, null_mut},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::*,
        NetworkManagement::{IpHelper::*, WindowsFilteringPlatform::*},
        Networking::WinSock::*,
        System::{Rpc::RPC_C_AUTHN_WINNT, Threading::*},
    },
};

const SUBLAYER: GUID = GUID::from_u128(0x677c691b_5d90_4cc7_b135_a6b467243001);
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn check(code: u32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "Windows WFP 錯誤 {code:#x}；請確認服務權限與系統狀態"
        ))
    }
}
pub struct Backend {
    engine: HANDLE,
    ids: Vec<u64>,
}
// The handle is only used behind the agent's runtime mutex.
unsafe impl Send for Backend {}
impl Backend {
    pub fn new() -> Result<Self, String> {
        unsafe {
            let session = FWPM_SESSION0 {
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txnWaitTimeoutInMSec: 5000,
                ..Default::default()
            };
            let mut engine = null_mut();
            check(FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_WINNT as u32,
                null(),
                &session,
                &mut engine,
            ))?;
            let mut backend = Self {
                engine,
                ids: vec![],
            };
            let mut name = wide("NetGuard 1.0.0");
            let layer = FWPM_SUBLAYER0 {
                subLayerKey: SUBLAYER,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: null_mut(),
                },
                weight: 0x7000,
                ..Default::default()
            };
            if let Err(e) = check(FwpmSubLayerAdd0(engine, &layer, null_mut())) {
                backend.stop();
                return Err(e);
            }
            Ok(backend)
        }
    }
    pub fn apply(&mut self, policy: &Policy) -> Result<ApplyReport, String> {
        let plan = compile_policy(policy, now(), "windows")?;
        unsafe {
            check(FwpmTransactionBegin0(self.engine, 0))?;
        }
        let result = (|| {
            for id in &self.ids {
                unsafe {
                    check(FwpmFilterDeleteById0(self.engine, *id))?;
                }
            }
            let mut ids = vec![];
            for (index, rule) in plan.rules.iter().enumerate() {
                for ipv6 in [false, true] {
                    if matches!(&rule.target, Target::Ip(ip) if ip.is_ipv6() != ipv6)
                        || matches!(&rule.target, Target::Network(n) if matches!(n, ipnet::IpNet::V6(_)) != ipv6)
                    {
                        continue;
                    }
                    ids.push(self.add_filter(rule, ipv6, u64::MAX - index as u64)?);
                }
            }
            unsafe {
                check(FwpmTransactionCommit0(self.engine))?;
            }
            Ok(ids)
        })();
        match result {
            Ok(ids) => {
                self.ids = ids;
                Ok(plan.report)
            }
            Err(e) => {
                unsafe {
                    FwpmTransactionAbort0(self.engine);
                }
                Err(e)
            }
        }
    }
    fn add_filter(&self, r: &Rule, ipv6: bool, mut weight: u64) -> Result<u64, String> {
        let mut conditions = Vec::new();
        let mut v4 = FWP_V4_ADDR_AND_MASK::default();
        let mut v6 = FWP_V6_ADDR_AND_MASK::default();
        let net = match r.target {
            Target::Ip(ip) => Some(ipnet::IpNet::from(ip)),
            Target::Network(n) => Some(n),
            _ => None,
        };
        if let Some(net) = net {
            let value = match net {
                ipnet::IpNet::V4(n) => {
                    v4.addr = u32::from(n.network());
                    v4.mask = u32::from(n.netmask());
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v4AddrMask: &mut v4,
                        },
                    }
                }
                ipnet::IpNet::V6(n) => {
                    v6.addr = n.network().octets();
                    v6.prefixLength = n.prefix_len();
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v6AddrMask: &mut v6,
                        },
                    }
                }
            };
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: value,
            });
        }
        if let Some(p) = r.protocol {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: p },
                },
            });
        }
        if let Some(p) = r.port {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: p },
                },
            });
        }
        let mut app_id = null_mut();
        if let Some(path) = &r.program {
            let path = wide(path);
            unsafe {
                check(FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app_id))?;
            }
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                },
            });
        }
        let mut name = wide(&r.name);
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            layerKey: if ipv6 {
                FWPM_LAYER_ALE_AUTH_CONNECT_V6
            } else {
                FWPM_LAYER_ALE_AUTH_CONNECT_V4
            },
            subLayerKey: SUBLAYER,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: if r.action == Action::Allow {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0;
        let code = unsafe { FwpmFilterAdd0(self.engine, &filter, null_mut(), &mut id) };
        if !app_id.is_null() {
            unsafe {
                FwpmFreeMemory0(&mut app_id as *mut _ as *mut *mut std::ffi::c_void);
            }
        }
        check(code)?;
        Ok(id)
    }
    pub fn stop(&mut self) {
        if !self.engine.is_null() {
            unsafe {
                FwpmEngineClose0(self.engine);
            }
            self.engine = null_mut();
            self.ids.clear();
        }
    }
    pub fn tick(&mut self) -> Result<(), String> {
        Ok(())
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.stop();
    }
}

fn program(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}
pub fn observe() -> Result<Vec<Flow>, String> {
    let mut flows = Vec::new();
    for ipv6 in [false, true] {
        let family = if ipv6 { AF_INET6 } else { AF_INET } as u32;
        let mut size = 0u32;
        unsafe {
            GetExtendedTcpTable(null_mut(), &mut size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0);
        }
        if size == 0 {
            continue;
        }
        // u64 backing keeps the native table properly aligned.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != 0 {
            return Err(format!("無法讀取 TCP 表：{rc}"));
        }
        let count = unsafe { *buf.as_ptr().cast::<u32>() } as usize;
        let row_size = if ipv6 {
            std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>()
        } else {
            std::mem::size_of::<MIB_TCPROW_OWNER_PID>()
        };
        if 4 + count * row_size > buf.len() * 8 {
            return Err("TCP 表長度不一致".into());
        }
        for index in 0..count.min(10000) {
            let ptr = unsafe { buf.as_ptr().cast::<u8>().add(4 + index * row_size) };
            let (ip, port, pid, state) = unsafe {
                if ipv6 {
                    let r = std::ptr::read_unaligned(ptr.cast::<MIB_TCP6ROW_OWNER_PID>());
                    (
                        IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                        u16::from_be(r.dwRemotePort as u16),
                        r.dwOwningPid,
                        r.dwState,
                    )
                } else {
                    let r = std::ptr::read_unaligned(ptr.cast::<MIB_TCPROW_OWNER_PID>());
                    (
                        IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                        u16::from_be(r.dwRemotePort as u16),
                        r.dwOwningPid,
                        r.dwState,
                    )
                }
            };
            if ip.is_unspecified() || port == 0 {
                continue;
            }
            flows.push(Flow {
                remote_ip: ip,
                remote_port: port,
                protocol: 6,
                program: program(pid),
                pid: Some(pid),
                hostname: None,
                observed_at: now(),
                state: format!("tcp:{state}"),
            });
        }
    }
    Ok(flows)
}
