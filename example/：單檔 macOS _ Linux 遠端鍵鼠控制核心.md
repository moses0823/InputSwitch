# `remote_input.rs`：單檔 macOS / Linux 遠端鍵鼠控制核心

本文件是交付說明。程式本體是單一檔案 `remote_input.rs`（5133 行），可整檔複製到任何 Rust 專案，加上下方依賴即可使用；不含 UI、Tauri、桌面視窗、設定檔或 IPC。

| 交付物 | 路徑 |
|---|---|
| 程式本體 | `src/remote_input.rs` |
| 依賴清單（可直接編譯的範例 manifest） | `Cargo.toml` |
| 本說明文件 | `remote_input_guide.md` |

---

## 1. 驗證狀態（請先讀這一節）

我沒有把「寫完了」當成「驗證過了」。實際做到的程度如下：

| 驗證項目 | 指令 | 結果 |
|---|---|---|
| Linux 型別檢查 | `cargo check` | 通過，**0 warning**（`-D warnings` 等級的乾淨度） |
| Linux 單元測試 | `cargo test --lib` | 14 項全過（codec、截斷、未知 frame、修飾鍵、KeySet、指紋、EventBuf） |
| 傳輸層整合測試 | `cargo test --test dtls_loopback` | 通過：DTLS 握手 + 雙向應用資料 |
| 引擎端對端測試 | `cargo test --test engine_e2e` | 通過：listener、指紋白名單、撥號、Hello 握手、未授權拒絕、無擷取時 `enable_remote_input()` 誠實報錯 |
| macOS 型別檢查 | `cargo check --target aarch64-apple-darwin`（見 §2.2） | 通過 |
| macOS 實機執行 | — | **未執行**（本環境無 macOS） |
| Linux 實機注入 / 擷取 | — | **未執行**（沙箱無 `/dev/input`、`/dev/uinput`） |
| 範例可編譯 | `cargo check --examples` | 通過（`examples/host.rs`、`examples/client.rs`） |

因此：**協定、傳輸、狀態機、錯誤處理已被自動測試覆蓋；`CGEventTap`／`CGEventPost`／`evdev`／`uinput` 的系統呼叫路徑只做到「編譯通過 + 依原始碼邏輯逐行對照」，沒有在真實桌面上按過一次鍵。** 這一項請在目標機器上以 §6 的範例自行驗收。

### 1.1 macOS 交叉檢查的方式與限制

`cargo check --target aarch64-apple-darwin` 會連帶編譯 `rustls → ring`，而 `ring` 需要 macOS 的 C 編譯器與 SDK，在 Linux 上必然失敗。為了仍能檢查 macOS 分支的型別正確性，我另外建了 `maccheck` 專案：把 `transport` 模組換成同簽章的 stub（`webrtc-dtls` 的 `Identity`／`dial_any`／`bind`／`ArcConn`／`BoxedListener`），其餘 5000 行原封不動，再對 `aarch64-apple-darwin` 編譯。結果通過，並且**在這個過程中抓出並修掉 4 個真實的 macOS 編譯錯誤**（`CGEventType` 沒有 `PartialEq`、`Modifiers::update` 誤用、`post_scroll` 需要 `&mut self`、未使用的 `CFRunLoopSource` 匯入）。也就是說，macOS 專屬程式碼不是「看起來對」，是真的被型別檢查過；但**連結與執行仍需在 macOS 上完成**。

---

## 2. 依賴（Cargo.toml）

```toml
[dependencies]
tokio = { version = "1.38", features = ["rt", "rt-multi-thread", "net", "sync", "time", "macros", "io-util"] }
thiserror = "2"
log = "0.4"
bitflags = "2"
sha2 = "0.10"
rustls = { version = "0.23", default-features = false, features = ["std", "ring"] }
webrtc-dtls = { version = "0.12", features = ["pem"] }
webrtc-util = "0.11"

[target.'cfg(target_os = "linux")'.dependencies]
libc = "0.2"

[target.'cfg(target_os = "macos")'.dependencies]
core-graphics = { version = "0.25", features = ["highsierra"] }
core-foundation = "0.10"
core-foundation-sys = "0.8"
keycode = "1.0"
```

各依賴存在的理由（沒有為了「看起來精簡」而拿掉必要項目）：

| 依賴 | 用途 |
|---|---|
| `tokio` | 引擎單一 async task、`select!`、UDP socket、通道、計時器。不需要 `full`。 |
| `webrtc-dtls` / `webrtc-util` / `rustls` | 原專案使用的 UDP + DTLS 傳輸與自簽憑證；`webrtc-dtls` 的 `Listener`／`Conn` trait 來自 `webrtc-util`。 |
| `sha2` | 憑證指紋（SHA-256），與原專案 `src/crypto.rs` 相同。 |
| `bitflags` | X11 風格的修飾鍵位元遮罩，與線上位元組一致。 |
| `thiserror` | `InputError`／`ProtocolError`。 |
| `log` | 只用 macro，不綁定任何 logger；由使用端決定輸出。 |
| `libc`（Linux） | `ioctl`（`EVIOCGRAB`／`EVIOCGNAME`／`EVIOCGBIT`／`UI_DEV_SETUP`…）、`read`／`write`、`inotify`。 |
| `core-graphics` / `core-foundation` / `core-foundation-sys`（macOS） | `CGEventTap`、`CGEventPost`、`CGDisplay`、`CFRunLoop`。 |
| `keycode`（macOS） | macOS virtual keycode ↔ evdev code 對照表（Chromium 表）。 |

系統需求：`rustls` 預設使用 `ring`，因此**需要 C 編譯器**（Linux：`build-essential`／`clang`；macOS：Xcode Command Line Tools）。除此之外沒有需要 `pkg-config` 的系統函式庫（`libinput`、`libei`、`libxkbcommon`、GTK 全都不需要）。

### 2.1 Linux 編譯

```bash
sudo apt install build-essential   # 只為了 ring 的 C 部分
cargo build --release              # x86_64-unknown-linux-gnu
cargo test                         # 單元測試 + 整合測試
```

### 2.2 macOS 編譯

```bash
xcode-select --install             # Command Line Tools（SDK + C 編譯器）
rustup target add aarch64-apple-darwin x86_64-apple-darwin

cargo build --release --target aarch64-apple-darwin   # Apple Silicon
cargo build --release --target x86_64-apple-darwin    # Intel
```

在同一個 repo 內同時編譯兩個 target 時，請使用 `--target`，否則 Cargo 會共用 `target/` 下的產物而互相覆蓋。

### 2.3 把單檔放進別的專案

```text
your-crate/
├── Cargo.toml        # 加上 §2 的依賴
└── src/
    ├── main.rs       # mod remote_input;  use remote_input::engine::RemoteInput;
    └── remote_input.rs
```

`remote_input.rs` 只依賴 crates.io 上的套件，不引用 Lan Mouse 專案的任何模組或路徑。

---

## 3. 權限需求

### 3.1 macOS

| 權限 | 觸發時機 | 沒給會怎樣 |
|---|---|---|
| **輔助使用（Accessibility）** | `CGEventTap` 建立、`CGEventPost` 注入 | `start_capture()` 回傳 `InputError::Capture("CGEventTap creation failed …")`；注入則由 `CGPreflightPostEventAccess()` 檢查後回傳 `InputError::EmulationPermission`。**不會假裝成功。** |
| **輸入監控（Input Monitoring）** | 讀取實體鍵盤事件 | tap 只能拿到部分事件或直接被系統停用；`TapDisabledByUserInput` 會回報 `DeviceDisconnect { DeviceLost }` 並記錄 error。 |

設定位置：系統設定 → 隱私權與安全性 → 輔助使用／輸入監控，加入你的執行檔（`cargo run` 時是 `target/debug/xxx`，建議先 `cargo build` 再對執行檔授權）。變更後需要重新啟動程式。

其他 macOS 行為：

- tap 若被系統以 timeout 停用，會自動 `CGEventTapEnable` 重新啟用（原始碼中處理 `TapDisabledByTimeout`）。
- 進入轉送狀態時會呼叫 `CGEventSourceSetLocalEventsSuppressionInterval(0.05)` 與私有的 `SetsCursorInBackground`，並在轉送期間隱藏／釘住游標，避免游標跑到畫面邊界外。

### 3.2 Linux

需要兩種權限，缺一不可，但**只有實際用到時才會要求**：

| 權限 | 對象 | 沒給會怎樣 |
|---|---|---|
| 讀取輸入裝置 | `/dev/input/event*` | `start_capture()` 回傳 `InputError::CapturePermission`，訊息中含 udev 規則範例 |
| 建立虛擬裝置 | `/dev/uinput` | 首次注入時回傳 `InputError::EmulationPermission`（`ensure_emulator()` 失敗），狀態 `last_error` 有內容，且**不會回 Ack**，對端因此不會誤以為取得控制權 |

設定方式（二選一）：

```bash
# A. 群組（重新登入才生效）
sudo groupadd -f input
sudo usermod -aG input "$USER"

# B. udev 規則（建議，插拔後仍有效）
sudo tee /etc/udev/rules.d/99-remote-input.rules >/dev/null <<'EOF'
KERNEL=="event*", SUBSYSTEM=="input", TAG+="uaccess"
KERNEL=="uinput", MODE="0660", GROUP="input"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger

sudo modprobe uinput                       # 需要 CONFIG_INPUT_UINPUT
echo uinput | sudo tee /etc/modules-load.d/uinput.conf   # 開機自動載入
```

`EVIOCGRAB`（獨佔擷取）只需要讀取權限即可，不需要 root。容器內執行需 `--device /dev/uinput --device /dev/input`。

Wayland 與 X11 都不需要額外權限：本檔不走 compositor 的 virtual-keyboard／libei／portal，而是直接對 kernel 的 evdev／uinput 說話。

---

## 4. 架構與流程（30 秒版）

```text
capture (macOS CGEventTap / Linux evdev+EVIOCGRAB)
        │  InputEvent（統一格式，bounded mpsc，key 事件 blocking_send、滑鼠移動 try_send）
        ▼
   Engine：單一 tokio task
        │  • 送出端狀態：local_keys / local_buttons / ModifierTracker / sync_seq
        │  • 接收端狀態：remote_keys / remote_buttons / last_sync_seq
        │  • 每 500 ms Ping、1 s 無封包即釋放、每 200 ms StateSync
        ├── ProtoEvent（二進位，big-endian，1 datagram = 1 frame）→ transport（UDP + DTLS）
        └── InputEvent → injection thread（macOS CGEventPost / Linux uinput），單一長期 OS thread
```

八個必要 API 全部對應到 `engine::RemoteInput` 的方法，另有 `start_listener()`／`stop_listener()`／`authorize_peer()`／`revoke_peer()`／`local_fingerprint()`／`shutdown()`。

### 4.1 統一事件格式

```rust
pub enum InputEvent {
    KeyboardKeyDown { key: u32, time: u32 },
    KeyboardKeyUp   { key: u32, time: u32 },
    MouseButtonDown { button: u32, time: u32 },
    MouseButtonUp   { button: u32, time: u32 },
    MouseMove       { dx: f64, dy: f64, time: u32 },   // 相對位移
    MouseWheel      { axis: u8, delta120: i32 },       // 120 = 一格
    MouseScroll     { axis: u8, pixels: f64, time: u32 }, // 觸控板像素級
    ModifierState   { depressed: u32, latched: u32, locked: u32, group: u32 },
    DeviceDisconnect{ reason: DisconnectReason },
    StateSync       { seq: u32, depressed: u32, locked: u32, buttons: u32, keys: KeySet },
}
```

- 鍵碼的**線上一律是 Linux evdev code**（`KeyA = 30`）。macOS 在擷取時用 `keycode` 表轉成 evdev，注入時再轉回 macOS virtual keycode，因此兩端不需要知道對方的按鍵碼體系。
- `KeySet` 是 `Copy`、無配置、上限 24 鍵的小集合，專門給 `StateSync` 用。
- 沒有任何 OS 原生事件結構被序列化；`CGEvent`／`libc::input_event` 只存在於各自的平台模組內。

### 4.2 傳輸：為什麼保留 UDP + DTLS

保留原專案設計（`webrtc-dtls` 0.12），沒有換成 TCP 或 QUIC：

**優點**：不需要自訂壅塞控制、不需要處理 TCP head-of-line blocking（滑鼠移動延遲不會被前面的鍵盤事件卡住）、DTLS 提供加密與對端憑證（指紋白名單）、無連線握手成本低、封包遺失時舊事件自動過期（本檔以 StateSync 修復狀態，見 §5）。

**缺點（實際會遇到的）**：不保證送達與順序 → 需要 `StateSync` 補償；NAT 穿透需要雙方在同網段或有 port forwarding（原專案靠 mDNS/手動設定，本檔只留 `connect_remote(host, port)`）；MTU 上限使單 frame 限 128 bytes（`MAX_FRAME_SIZE`）；DTLS 握手需要自簽憑證，第一次連線必須先交換指紋。

線上位元組與原專案一致：frame id 0–11（`PointerMotion=0` … `Hello=11`）的欄位順序、大小、big-endian 全部照抄，另加 `DeviceDisconnect=12`、`StateSync=13`。因此本檔與 Lan Mouse 之間可以互通指標與鍵盤事件（新增的兩個 frame 對舊版而言是「未知 frame」，會被安全地忽略）。

---

## 5. 輸入狀態同步（最容易出事的部分）

| 情境 | 處理方式 | 程式位置 |
|---|---|---|
| 重複的按下 | 送出端 `local_keys.insert()` 失敗即丟棄；注入端 `remote_keys.insert()` 失敗即丟棄 | `on_local_event`／`inject` |
| 封包遺失造成卡鍵 | 每 200 ms 送一次 `StateSync`（權威狀態：按下的鍵、滑鼠鍵位元、修飾鍵），注入端做差異比對，補送 key-up／key-down | `state_sync_event`／`reconcile` |
| 亂序／過期的 StateSync | 以 `seq` 判斷，舊快照直接丟棄 | `reconcile` |
| 連線中斷 | 該 peer 若正在注入 → `ReleaseAll`；送出端把仍按下的鍵合成 key-up 後才離線 | `on_net`／`release_forwarded` |
| 切換控制權 | 同一時間只允許一個 peer 注入；新的 `Enter` 會先釋放舊 peer 的全部按鍵 | `on_enter` |
| 1 秒收不到任何封包 | 判定 peer 死亡：釋放按鍵、關閉連線、從狀態移除 | `on_tick` |
| 停止擷取／關閉轉送／緊急鍵 | 合成 key-up + `Modifiers(0)` + 空 `StateSync`，再送 `Leave`／`DeviceDisconnect` | `release_forwarded`／`stop_capture_inner`／`disable_forwarding` |
| 對端回報裝置遺失 | 立刻 `ReleaseAll`，不等 watchdog | `inject(DeviceDisconnect)` |
| 緊急釋放鍵 | `Config::release_bind`（預設空 = 關閉；`with_default_release_bind()` 可設為 Ctrl+Alt+Esc）：全部按鍵同時按住即停止轉送並釋放 | `release_bind_held` |

原專案只有「1 秒 watchdog」與「合成 key-up」；`StateSync` 是本次新增，補上「封包遺失但連線仍活著」這個原專案處理不到的情境。

---

## 6. API 使用範例

以下兩段可直接編譯的完整版本在 `examples/host.rs`、`examples/client.rs`（`cargo check --examples` 已通過；因為是同一 crate 內的範例，路徑寫成 `remote_input_core::`，放進你自己的專案時改成 `remote_input::`）。

### 6.1 最小可跑範例（A 機：把自己的鍵鼠送出去）

```rust
// 需要 tokio 的 "signal" feature（只用於 Ctrl-C，可換成你自己的關閉條件）
use remote_input::engine::{Config, RemoteInput};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = RemoteInput::new(Config::new().with_listen_port(4242))?;

    let port = host.start_listener().await?;
    println!("listening on UDP {port}");
    println!("my fingerprint: {}", host.local_fingerprint()); // 給對端授權用

    // B 機的指紋（第一次連線前先取得，例如由使用者輸入或先跑一次 B 印出來）
    host.authorize_peer("b3a1…（64 個 hex 字元）").await?;

    host.start_capture().await?;        // 開啟擷取（此時仍本機可用）
    host.enable_remote_input().await?;  // 獨佔本機輸入並開始轉送

    tokio::signal::ctrl_c().await?;
    host.release_all_inputs().await?;
    host.shutdown().await;
    Ok(())
}
```

### 6.2 B 機：接收並注入

```rust
use remote_input::engine::{Config, RemoteInput};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 若 A 機要求釘選憑證，可用 with_pinned_peer("<A 的指紋>")
    let client = RemoteInput::new(Config::new())?;
    println!("my fingerprint: {}", client.local_fingerprint());

    client.connect_remote("192.168.1.20", 4242).await?;

    // 之後完全由事件驅動：
    //  收到 Enter  → 自動 Ack，開始把遠端事件注入本機（失敗則不 Ack）
    //  收到 Leave  → 釋放全部按鍵
    //  1 秒無封包 → 釋放全部按鍵並關閉連線
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let st = client.get_connection_status();
        println!("{st:?}");
    }
}
```

### 6.3 狀態查詢與緊急處置

```rust
let status = client.get_connection_status();      // 同步、不阻塞、不做 I/O
assert!(status.capture_active || !status.forwarding);
for peer in &status.peers {
    println!("{} rtt={:?} injecting={}", peer.addr, peer.rtt_ms, peer.injecting_from_peer);
}
if let Some(err) = &status.last_error {
    eprintln!("last error: {err}");               // 權限問題一定會出現在這裡
}

client.release_all_inputs().await?;               // 兩端都釋放
client.disable_remote_input().await?;             // 停止轉送（送出合成 key-up + Leave）
```

### 6.4 行為契約（請依此設計上層）

| 呼叫 | 前置條件 | 失敗時 |
|---|---|---|
| `start_capture()` | 有權限 | `CapturePermission` / `NoInputDevice` / `Capture`，狀態不變 |
| `enable_remote_input()` | 必須先 `start_capture()` 成功 | `InputError::Capture("start_capture() must succeed …")`，並寫入 `last_error` |
| `connect_remote()` | — | `ConnectTimeout`（DTLS 握手逾時）或 `Network`（被白名單拒絕時就是握手失敗） |
| `enable_remote_input()` 後 | 對端需回 `Ack` | 未回 Ack 的 peer 不會收到事件（狀態 `forwarding_to_peer=false`） |
| 注入端 | 需要 `/dev/uinput` 或 Accessibility | 不送 `Ack`、`Pong(false)`、`last_error` 有訊息 |
| `get_connection_status()` | 任何時候 | 回傳快照，永不 panic（鎖中毒也會取回） |

`RemoteInput::new()` 必須在 tokio runtime 內呼叫（內部用 `Handle::try_current()`，不在 runtime 內會回 `InputError::NotRunning`，不會 panic）。一個行程建議只建立一個引擎。

---

## 7. 與原專案的差異

| 項目 | Lan Mouse（上游） | 本檔 | 為什麼 |
|---|---|---|---|
| Linux 擷取 | `wlr-layer-shell` 視窗 + `pointer-constraints` + `relative-pointer` + keyboard-shortcuts-inhibit（需要每個螢幕邊緣一個 surface） | **evdev + `EVIOCGRAB`** | 單檔、無 UI 不可能建立 layer-shell surface；evdev 與顯示伺服器無關，Wayland/X11 皆可 |
| Linux 注入 | wlroots virtual-keyboard/pointer、libei、xdg-desktop-portal RemoteDesktop、X11 XTEST | **uinput 虛擬鍵盤 + 虛擬指標** | 不需合成器支援或 portal 授權流程；兩種顯示伺服器一致 |
| 螢幕邊界偵測 | 有（游標碰到邊緣即切換） | **無**，由 `enable_remote_input()`／`disable_remote_input()` 決定 | 需要知道螢幕幾何與多螢幕佈局，屬 UI/桌面整合 |
| 連線探索 | mDNS + 設定檔 + GUI 配對 | 只有 `connect_remote(host, port)` 與指紋白名單 | 屬應用層 |
| 協定 frame | 0–11 | 0–11 **位元組完全相同**，新增 12 `DeviceDisconnect`、13 `StateSync` | 保留互通性，同時補上狀態修復能力 |
| 封包遺失修復 | 只靠 1 s watchdog | watchdog + **每 200 ms StateSync 差異修復** | 連線活著但漏封包時，原設計會卡鍵直到斷線 |
| macOS `FlagsChanged` 判斷 | `depressed > previous` 比較整個遮罩 | 比對**該鍵自己的** flag bit | 原寫法在「按住 Control 時放開 Shift」會誤判 |
| 撥號端憑證驗證 | `insecure_skip_verify = true`（無 pin） | 同樣預設，但可用 `Config::with_pinned_peer()` 釘選 | 不破壞相容性，同時提供更安全的選項 |
| 監聽端認證 | `RequireAnyClientCert` + 指紋白名單，拒絕用 `ErrVerifyDataMismatch` | 相同 | 直接移植 |
| 憑證 | 每次安裝產生一組，存檔重用 | 每次 `RemoteInput::new()` 產生一組（記憶體中） | 無設定檔；長期部署請自行保存並提供載入介面 |
| 鍵盤重複 | 各平台自行處理 | macOS 由注入執行緒產生；Linux 交給 kernel（`EV_REP`） | 與原專案一致的策略 |
| 擷取開關 | 由 barrier 狀態機驅動 | `start_capture()` 為被動、`enable_remote_input()` 才獨佔 | 讓兩個 API 開關在兩個平台上語意一致 |
| UI / Tauri / 設定 / IPC / tray | 有 | 全部移除 | 任務要求 |

### 7.1 原專案有、本檔刻意保留的細節

- macOS：tap 掛在 `Session` + `HeadInsertEventTap` + `Default` 選項；吞掉事件時把 `CGEvent` 型別設為 `Null`；`TapDisabledByTimeout` 自動重啟；`TapDisabledByUserInput` 視為不可恢復並回報 `DeviceLost`。
- macOS 注入：`CGEventTapLocation::HID`、修飾鍵用 `FlagsChanged` + 真實 keycode + `NX_DEVICE_L_*` 位元 + `CGEventFlagNonCoalesced`、方向鍵補 `NumericPad|SecondaryFn`、拖曳時改用 `*MouseDragged`、多擊 `click_state`、螢幕空間夾制、自然捲動反向。
- Linux 擷取：只挑有鍵盤／指標能力的裝置（`EVIOCGBIT` 能力探測）、`inotify` 監看 `/dev/input` 熱插拔、裝置消失時合成該裝置按鍵的 release、`REL_WHEEL_HI_RES` 與 `REL_WHEEL` 雙軌。
- Linux 注入：鍵盤與指標分成兩個 uinput 裝置（部分 libinput 版本會誤判單一複合裝置）、`EV_REP` 讓 kernel 產生重複、`REL_WHEEL_HI_RES` 累積換算、關閉時 `UI_DEV_DESTROY` 不留下殘留節點。
- 傳輸：多個解析位址並行撥號、`JoinSet` 取第一個成功、`Hello` 交換建置識別、`Ping`/`Pong(alive)`、無法解碼的 datagram 只記錄不中斷連線。

---

## 8. 尚未實作或無法保證的功能

程式內以 `LIMITATIONS` 常數記錄同一份清單，方便隨檔案流通：

1. **沒有邊界偵測**：哪一台機器收到輸入由呼叫端決定（`enable_remote_input()`／`disable_remote_input()`），不是由游標位置決定。
2. **沒有 mDNS 探索、設定檔、IPC/GUI、tray、enter/leave hook**。
3. **撥號端不驗 CA**（與上游相同，`insecure_skip_verify`）；可用 `Config::with_pinned_peer()` 釘選指紋。監聽端一定驗客戶端憑證。
4. **線上不強制順序**；順序問題由 `StateSync` 在一個同步週期內修復（≤200 ms 的卡鍵窗口，之後必定收斂）。
5. **沒有絕對座標定位**（繪圖板、`wl_pointer.set_cursor`）；只傳相對位移。
6. **X11 擷取未實作**（上游的 `input-capture/src/x11.rs` 也是 `NotImplemented`）；X11 下請走 evdev。
7. **macOS 多螢幕夾制已移植，但螢幕熱插拔要等下一次移動事件才生效。**
8. **Linux 熱插拔靠 inotify**；沒有 inotify 的容器只會在下一次 rescan 才看到新裝置。
9. **`stop_listener()` 會一併關閉該 listener 接受的連線**：`webrtc-util` 的 listener 同時持有 UDP socket 與「把封包分派給已接受連線」的迴圈，只丟掉 listener 會讓那些連線變成半死（能送不能收）。這是實測發現的行為，已寫進程式註解。
10. **注入佇列沒有深度上限**：注入執行緒使用一個 `std::sync::mpsc`，寧可堆積也不丟 key-up。
11. **鍵盤重複的時序**在 macOS（本檔產生）與 Linux（kernel 產生）略有差異。
12. **未在 macOS 實機、未在具備 `/dev/uinput` 的機器上執行過**（見 §1）；系統呼叫層的錯誤碼對照（`EPERM`／`ENOENT` → 對應的中文/英文提示）已寫好，但沒有實際觸發驗證。

---

## 9. 需求對照表

| 任務要求 | 實作位置 | 做法 |
|---|---|---|
| 不用輪詢處理網路事件 | `engine::run` | 每個連線一個 `recv` task → 單一 `mpsc`；主迴圈 `select!` 等待「事件」或「計時器」，不輪詢 socket |
| 事件驅動 | 同上 | 擷取回呼、socket、指令、計時器四路 `select!` |
| 不用 JSON | `proto` | 固定長度 big-endian 二進位，`encode`／`decode` 皆為純函式 |
| UI 不參與傳輸 | 全檔 | 沒有 UI 型別；`RemoteInput` 是唯一入口 |
| 避免不必要配置 | `EventBuf`、`KeySet` | 擷取回呼內的輸出用固定 8 格堆疊緩衝；`StateSync` 用 `Copy` 集合；發送緩衝用 `[u8; 128]` 堆疊陣列 |
| 不為每個滑鼠移動建執行緒 | `engine`／`inject` | 全程只有：引擎 task、每連線 1 個讀取 task、1 個注入 OS thread、擷取本身的執行緒 |
| 保證按下／放開順序 | `inject`、`reconcile` | 同一 key 的 down/up 走同一條 FIFO 通道到注入執行緒；重複按下被丟棄；StateSync 只補差異 |
| 斷線不得永久卡鍵 | `on_tick`、`release_forwarded`、`release_injected` | 1 s 無封包即釋放；送出端合成 key-up；`Drop`/`shutdown` 亦釋放 |
| 不以虛假成功掩蓋權限錯誤 | `linux_capture::start`、`uinput_error`、`mac_capture::create_tap`、`ensure_emulator` | 權限不足一律回 `InputError::*Permission`，並寫入 `ConnectionStatus::last_error`；注入不可用時**不送 Ack** |
| 單檔、條件編譯 | 檔頭 `compile_error!` + `#[cfg(target_os=…)]` | 非 macOS/Linux 直接 `compile_error!`，不假裝支援 |

---

## 10. 授權

- 上游 **Lan Mouse** 為 **GPL-3.0-or-later**（根目錄 `LICENSE`，各子 crate `Cargo.toml` 亦宣告 `GPL-3.0-or-later`）。
- 本檔為其衍生作品，**同樣以 GPL-3.0-or-later 釋出**，不得改標為 MIT／Apache-2.0。檔頭已保留原始著作權聲明（`Copyright (C) 2023-2025 Ferdinand Schober and Lan Mouse contributors`）與衍生說明。
- 實際閱讀並參考的檔案（`PROVENANCE` 常數亦列出）：

| 檔案 | 取用方式 |
|---|---|
| `lan-mouse-proto/src/lib.rs` | 改寫（frame 佈局與 codec 重新實作，位元組相容） |
| `input-event/src/lib.rs`、`input-event/src/scancode.rs` | 改寫（事件分類與 evdev 常數，未複製 851 行對照表） |
| `input-capture/src/lib.rs`、`input-capture/src/macos.rs` | 改寫（CGEventTap 流程與修飾鍵判斷） |
| `input-capture/src/layer_shell.rs` | 僅閱讀語意，**未移植**（改為 evdev） |
| `input-emulation/src/lib.rs`、`input-emulation/src/macos.rs`、`input-emulation/src/wlroots.rs` | 改寫（注入流程、修飾鍵簿記） |
| `src/connect.rs`、`src/listen.rs`、`src/crypto.rs` | 改寫（DTLS 撥號／監聽、指紋） |
| `src/capture.rs`、`src/emulation.rs` | 改寫（狀態機、watchdog、Enter/Ack） |
| `input-emulation/src/{x11,libei,xdg_desktop_portal,windows}.rs`、`input-capture/src/{x11,libei}.rs` | 僅閱讀，未使用 |

- 完全獨立重實作（非上游程式碼）：`engine` 模組（狀態機、指令通道、`RemoteInput` 公開 API、`ConnectionStatus`）、`StateSync`／`DeviceDisconnect` frame、Linux `evdev`／`uinput` 的 ioctl 封裝、`EventBuf`／`KeySet`。
- 散布本檔時請一併提供 GPL-3.0 全文（上游 `LICENSE` 可直接取用）與本說明。
