mod remote_input;

use tauri::State;
use tokio::sync::Mutex;

use remote_input::engine::{Config, ConnectionStatus, RemoteInput};

struct AppState {
    engine: Mutex<Option<RemoteInput>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self { engine: Mutex::new(None) }
    }
}

#[derive(Clone, serde::Serialize)]
struct StatusView {
    capture_active: bool,
    forwarding: bool,
    listening_port: Option<u16>,
    connected: bool,
    injecting: bool,
    emulation_ready: bool,
    local_fingerprint: String,
    peers: usize,
    last_error: Option<String>,
}

fn view(status: ConnectionStatus) -> StatusView {
    StatusView {
        capture_active: status.capture_active,
        forwarding: status.forwarding,
        listening_port: status.listening_port,
        connected: status.is_connected(),
        injecting: status.injecting(),
        emulation_ready: status.emulation_ready,
        local_fingerprint: status.local_fingerprint,
        peers: status.peers.len(),
        last_error: status.last_error,
    }
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<StatusView, String> {
    let guard = state.engine.lock().await;
    Ok(match guard.as_ref() {
        Some(engine) => view(engine.get_connection_status()),
        None => view(ConnectionStatus::default()),
    })
}

#[tauri::command]
async fn start_host(state: State<'_, AppState>, port: u16) -> Result<StatusView, String> {
    let engine = RemoteInput::new(Config::new().with_listen_port(port)).map_err(|e| e.to_string())?;
    let listening_port = engine.start_listener().await.map_err(|e| e.to_string())?;
    engine.start_capture().await.map_err(|e| e.to_string())?;
    let status = engine.get_connection_status();
    *state.engine.lock().await = Some(engine);
    Ok(view(ConnectionStatus { listening_port: Some(listening_port), ..status }))
}

#[tauri::command]
async fn authorize_peer(state: State<'_, AppState>, fingerprint: String) -> Result<(), String> {
    let guard = state.engine.lock().await;
    let engine = guard.as_ref().ok_or("Host 尚未啟動")?;
    engine.authorize_peer(&fingerprint).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn revoke_peer(state: State<'_, AppState>, fingerprint: String) -> Result<(), String> {
    let guard = state.engine.lock().await;
    let engine = guard.as_ref().ok_or("Host 尚未啟動")?;
    engine.revoke_peer(&fingerprint).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn connect_remote(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    host_fingerprint: String,
) -> Result<StatusView, String> {
    let mut config = Config::new().with_listen_port(port);
    if !host_fingerprint.trim().is_empty() {
        config = config.with_pinned_peer(host_fingerprint.trim()).map_err(|e| e.to_string())?;
    }
    let engine = RemoteInput::new(config).map_err(|e| e.to_string())?;
    engine.connect_remote(&host, port).await.map_err(|e| e.to_string())?;
    engine.start_capture().await.map_err(|e| e.to_string())?;
    let status = view(engine.get_connection_status());
    *state.engine.lock().await = Some(engine);
    Ok(status)
}

#[tauri::command]
async fn switch_control(state: State<'_, AppState>, remote: bool) -> Result<StatusView, String> {
    let guard = state.engine.lock().await;
    let engine = guard.as_ref().ok_or("尚未建立連線")?;
    if remote {
        engine.enable_remote_input().await.map_err(|e| e.to_string())?;
    } else {
        engine.disable_remote_input().await.map_err(|e| e.to_string())?;
    }
    Ok(view(engine.get_connection_status()))
}

#[tauri::command]
async fn release_all(state: State<'_, AppState>) -> Result<StatusView, String> {
    let guard = state.engine.lock().await;
    let engine = guard.as_ref().ok_or("尚未建立連線")?;
    engine.release_all_inputs().await.map_err(|e| e.to_string())?;
    Ok(view(engine.get_connection_status()))
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<StatusView, String> {
    let engine = state.engine.lock().await.take();
    if let Some(engine) = engine {
        let _ = engine.release_all_inputs().await;
        let _ = engine.disconnect_remote().await;
        let _ = engine.stop_listener().await;
        let _ = engine.stop_capture().await;
        engine.shutdown().await;
    }
    Ok(view(ConnectionStatus::default()))
}

#[tauri::command]
fn local_ip() -> String {
    get_if_addrs::get_if_addrs()
        .ok()
        .and_then(|interfaces| {
            interfaces
                .into_iter()
                .filter(|interface| !interface.is_loopback())
                .filter_map(|interface| match interface.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip.to_string()),
                    _ => None,
                })
                .next()
        })
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_host,
            authorize_peer,
            revoke_peer,
            connect_remote,
            switch_control,
            release_all,
            disconnect,
            local_ip
        ])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
