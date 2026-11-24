//! # `remote_input` — a standalone remote keyboard/mouse control core for macOS and Linux
//!
//! This module is a single-file extraction of the *remote input control mechanism* of the
//! **Lan Mouse** project (<https://github.com/feschber/lan-mouse>): local input capture, a
//! platform-neutral binary event format, an encrypted UDP transport, remote input injection and
//! input-state synchronisation. Everything that is not part of that mechanism (GTK/Adwaita UI,
//! Tauri shell, configuration files, IPC with a GUI, tray icons, onboarding, mDNS discovery,
//! enter/leave hooks, ...) has been left out.
//!
//! ## Provenance and licensing
//!
//! Lan Mouse is licensed **GPL-3.0-or-later**. Every source file read for this extraction carries
//! `license = "GPL-3.0-or-later"` in its `Cargo.toml` (`input-event`, `input-capture`,
//! `input-emulation`, `lan-mouse-proto`, and the root crate). This file is a derivative work and is
//! therefore released under **GPL-3.0-or-later** as well; it must not be relicensed as MIT or
//! Apache-2.0.
//!
//! Original code: Copyright (C) 2023-2025 Ferdinand Schober and Lan Mouse contributors.
//! Extracted, restructured and in parts re-implemented: 2025, for this single-file build.
//!
//! The upstream files that were actually read and the way each influenced this file are listed in
//! [`PROVENANCE`]; the summary is:
//!
//! | upstream file | what was taken | how |
//! |---|---|---|
//! | `lan-mouse-proto/src/lib.rs` | wire layout of all frames, `MAX_EVENT_SIZE`, big-endian codec | ported, frame ids 0-11 byte-identical, two new ids added |
//! | `input-event/src/lib.rs` | the pointer/keyboard event taxonomy (`Motion`/`Button`/`Axis`/`AxisDiscrete120`, `Key`/`Modifiers`) and the `BTN_*` constants | ported into a flat, allocation-free enum |
//! | `input-event/src/scancode.rs` | the fact that **Linux evdev keycodes are the canonical wire code**; `Linux::*` names used for modifier classification | re-implemented (only the constants that are needed, not the 851-line table) |
//! | `input-capture/src/macos.rs` | CGEventTap setup (session tap, head insert, `Default` options), the capture/pass-through decision, `FlagsChanged` → modifier mapping, scroll-wheel natural-scroll correction, `TapDisabledBy*` handling, `CGEventSourceSetLocalEventsSuppressionInterval` + `SetsCursorInBackground` | ported and adapted (cursor warping simplified to a pinned anchor, no display/barrier logic) |
//! | `input-capture/src/layer_shell.rs` | the *semantics* of Wayland capture (relative motion, pointer lock, keyboard grab) | **not** ported; replaced by an evdev grab (see "Deviations") |
//! | `input-capture/src/lib.rs` | `pressed_keys` tracking, `take_pressed_keys`, `keys_pressed` release-chord check | ported |
//! | `input-emulation/src/macos.rs` | `CGEventPost` at the `HID` tap location, `FlagsChanged` events carrying real key codes and `NX_DEVICE_*` bits, click-state tracking, drag event selection, screen-space clamping, natural-scroll replication, key repeat | ported and adapted (repeat implemented without a second task) |
//! | `input-emulation/src/lib.rs` | per-handle `pressed_keys` set, duplicate-press suppression, `release_keys` on destroy | ported |
//! | `input-emulation/src/wlroots.rs` | modifier bookkeeping (`XMods`, `update_by_key_event`, `mask_pressed`/`mask_locks`) | ported into [`keymap::ModifierTracker`] |
//! | `src/connect.rs` | UDP + DTLS dial, parallel dial over several addresses, ping/pong liveness, per-datagram receive loop, "skip undecodable datagram" forward-compatibility | ported |
//! | `src/listen.rs` | DTLS listener with `RequireAnyClientCert` + fingerprint allow-list, accept loop, per-connection read loop | ported |
//! | `src/capture.rs` | host state machine (`WaitingForAck` → `Sending`), synthesised key-ups + modifier reset + `Leave` on release, release-bind | ported |
//! | `src/emulation.rs` | client-side dedup, 1 s peer watchdog that releases keys, `Enter` → `Ack` reply | ported |
//! | `src/crypto.rs` | certificate fingerprint (SHA-256 hex) | ported |
//!
//! ## Architecture
//!
//! ```text
//!   ┌──────────────┐   InputEvent    ┌───────────────────────────────────────┐
//!   │ capture      │ ──────────────► │  Engine (single tokio task)           │
//!   │  macOS: tap  │  mpsc (bounded) │   • host state  (pressed keys/buttons)│
//!   │  Linux: evdev│                 │   • peer state  (per-peer key sets)   │
//!   └──────────────┘                 │   • watchdog, ping/pong, state sync   │
//!                                    └───────┬───────────────────────┬───────┘
//!                                            │ ProtoEvent            │ InputEvent
//!                                    ┌───────▼────────┐      ┌───────▼────────┐
//!                                    │ transport      │      │ emulation      │
//!                                    │ UDP + DTLS     │      │ macOS: CGEvent │
//!                                    │ (webrtc-dtls)  │      │ Linux: uinput  │
//!                                    └────────────────┘      └────────────────┘
//! ```
//!
//! Everything runs on **one** engine task; capture callbacks push into a bounded channel, the
//! injection side is one long-lived OS thread (both platform APIs want a stable thread). No event
//! creates a thread, no network I/O is polled, and no JSON is involved.
//!
//! ## Public API
//!
//! [`engine::RemoteInput`] is the entry point. Every method is `async` except the two accessors.
//!
//! | method | effect |
//! |---|---|
//! | `start_capture()` | open the platform capture backend; passive until forwarding is enabled |
//! | `stop_capture()` | close it and release every held key locally and remotely |
//! | `connect_remote(host, port)` | UDP+DTLS dial; with several resolved addresses the first successful handshake wins |
//! | `disconnect_remote()` | close the dialled connection and release its keys |
//! | `enable_remote_input()` | grab local input and forward it (`Enter`/`Ack` handshake) |
//! | `disable_remote_input()` | stop forwarding, synthesise key-ups, send `Leave` |
//! | `release_all_inputs()` | release every key and button on both sides |
//! | `get_connection_status()` | non-blocking snapshot of the engine state |
//! | `start_listener()` / `stop_listener()` | serve peers (UDP+DTLS, client certificate required) |
//! | `authorize_peer(hex)` / `revoke_peer(hex)` | manage the listener's fingerprint allow-list |
//! | `local_fingerprint()` | the value the peer has to authorize |
//! | `shutdown()` | stop everything and join the engine |
//!
//! A listener owns the UDP socket *and* the demultiplexing loop that feeds already accepted
//! connections, so `stop_listener()` also closes those connections (after releasing their keys).
//! Keep one engine alive per process; nothing here is global.
//!
//! ## Deviations from upstream (see also [`LIMITATIONS`])
//!
//! 1. **Linux capture uses evdev instead of `wlr-layer-shell` + `wl_pointer`.** Upstream needs a
//!    Wayland surface on every screen edge (i.e. a window), a compositor implementing
//!    `wlr-layer-shell`, pointer-constraints and relative-pointer. A single-file core without UI
//!    cannot create such surfaces, and this extraction explicitly targets evdev. `EVIOCGRAB` on
//!    `/dev/input/event*` is display-server agnostic and therefore also works under Wayland.
//! 2. **Linux injection uses `uinput` instead of the wlroots/libei/portal backends.** Same reason:
//!    no compositor cooperation required, works on Wayland and X11 alike.
//! 3. **New frames** `DeviceDisconnect` (12) and `StateSync` (13); ids 0-11 keep upstream's exact
//!    byte layout, so an upstream peer can still exchange pointer/keyboard input with this file.
//! 4. **`StateSync` reconciliation** replaces upstream's "hope the key-up arrives" approach: the
//!    host periodically re-sends the authoritative pressed-key set and the client reconciles, so a
//!    lost or reordered key-up cannot leave a key stuck for more than one sync interval.
//! 5. **`FlagsChanged` press/release detection** compares the modifier's own flag bit instead of
//!    upstream's `depressed > previous` bitmask comparison, which mis-detects the release of Shift
//!    while Control is still held.
//! 6. **`start_capture()` is passive**: it opens/arms capture but does not steal local input.
//!    `enable_remote_input()` performs the exclusive grab. This keeps the two API switches
//!    independent on both platforms (macOS returns `Keep` from the tap while passive, Linux leaves
//!    the evdev device ungrabbed).
//!
//! ## Compile
//!
//! ```text
//! macOS : cargo build --release --target aarch64-apple-darwin   (or x86_64-apple-darwin)
//! Linux : cargo build --release
//! ```

#![allow(clippy::too_many_arguments)]

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!(
    "remote_input.rs implements macOS and Linux only; refusing to pretend otherwise. \
     Add a platform backend instead of compiling this file on another target."
);

pub use proto::{Direction, DisconnectReason, InputEvent, KeySet, Modifiers, ProtoEvent};

/// Upstream files that this file was derived from, for auditability.
pub const PROVENANCE: &[(&str, &str)] = &[
    ("lan-mouse-proto/src/lib.rs", "frame layout, big-endian codec"),
    ("input-event/src/lib.rs", "event taxonomy, BTN_* constants"),
    ("input-event/src/scancode.rs", "evdev as canonical key code, modifier names"),
    ("input-capture/src/lib.rs", "pressed-key tracking, release-chord check"),
    ("input-capture/src/macos.rs", "CGEventTap capture"),
    ("input-capture/src/layer_shell.rs", "Wayland capture semantics (replaced by evdev)"),
    ("input-emulation/src/lib.rs", "per-handle dedup, release-on-destroy"),
    ("input-emulation/src/macos.rs", "CGEventPost injection"),
    ("input-emulation/src/wlroots.rs", "modifier bookkeeping"),
    ("src/connect.rs", "UDP/DTLS dial, ping/pong, receive loop"),
    ("src/listen.rs", "DTLS listener, fingerprint allow-list"),
    ("src/capture.rs", "host state machine, key-up synthesis, Leave"),
    ("src/emulation.rs", "client dedup, 1 s watchdog, Enter/Ack"),
    ("src/crypto.rs", "SHA-256 certificate fingerprint"),
];

/// Known gaps of this extraction. Kept in the code so that it travels with the file.
pub const LIMITATIONS: &[&str] = &[
    "No barrier/edge detection: which machine receives input is decided by the API caller \
     (enable_remote_input/disable_remote_input), not by cursor position.",
    "No mDNS discovery, no config file, no IPC/GUI, no enter/leave hooks, no tray icon.",
    "The dial side does not verify the peer certificate against a CA (insecure_skip_verify, as \
     upstream); it can be pinned with Config::expected_peer_fingerprint. The listening side always \
     authenticates clients by fingerprint.",
    "Frame ordering is not enforced on the wire; ordering is repaired by StateSync within one sync \
     interval (deviation 4).",
    "Linux keyboard auto-repeat is generated by the kernel for the uinput device, macOS repeat is \
     generated by this file; the two differ slightly in timing.",
    "Absolute pointer positioning (tablets, wl_pointer.set_cursor) is not implemented; only \
     relative motion is transported.",
    "X11 input capture is not implemented (upstream returns NotImplemented for it as well).",
    "macOS multi-display clamping is ported, but a display hot-plug is only picked up on the next \
     motion event.",
    "Linux device hot-plug is detected through inotify on /dev/input; devices created inside a \
     container without inotify support are only picked up on the next rescan.",
    "stop_listener() also closes connections that were accepted by that listener, because \
     webrtc-util's listener owns the demultiplexing loop that delivers packets to them.",
    "There is no input-injection queue depth limit: the injection thread has one unbounded \
     std::sync::mpsc channel, so a stalled uinput/CGEventPost cannot drop a key-up.",
    "Key repeat while forwarding: Linux lets the kernel repeat for the virtual device, macOS \
     repeats inside the injection thread. Both are local behaviour of the *receiving* machine; the \
     sender only ever transports one key-down.",
];

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Everything that can go wrong. Permission problems are always reported as errors; this file
/// never pretends to be capturing or injecting when the OS refused.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("input capture is not permitted: {0}")]
    CapturePermission(String),
    #[error("input injection is not permitted: {0}")]
    EmulationPermission(String),
    #[error("no usable input device: {0}")]
    NoInputDevice(String),
    #[error("input capture failed: {0}")]
    Capture(String),
    #[error("input injection failed: {0}")]
    Emulation(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("connection to {addr} timed out")]
    ConnectTimeout { addr: SocketAddr },
    #[error("peer {0} is not in the authorized fingerprint list")]
    PeerNotAuthorized(String),
    #[error("peer closed the connection")]
    NotConnected,
    #[error("protocol violation: {0}")]
    Protocol(#[from] proto::ProtocolError),
    #[error("engine is not running")]
    NotRunning,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, InputError>;

/// Commands for the platform injection thread.
#[derive(Clone, Copy, Debug)]
pub enum EmuCommand {
    Event(InputEvent),
    /// Release every key and button that is currently held.
    ReleaseAll,
    Shutdown,
}

/// Fixed-capacity event buffer. Capture callbacks run on OS threads and must not allocate per
/// event; this is what a single OS input event can expand into (a modifier change is one key event
/// plus one modifier-state event, a scroll can be two axes).
pub struct EventBuf {
    items: [InputEvent; 8],
    len: usize,
}

impl EventBuf {
    pub fn new() -> Self {
        Self {
            items: [InputEvent::MouseMove { dx: 0.0, dy: 0.0, time: 0 }; 8],
            len: 0,
        }
    }

    pub fn push(&mut self, event: InputEvent) {
        if self.len < self.items.len() {
            self.items[self.len] = event;
            self.len += 1;
        } else {
            log::warn!("event buffer overflow, dropping {event}");
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &InputEvent> {
        self.items[..self.len].iter()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for EventBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------------
// Protocol: platform-neutral event format + binary codec
// ---------------------------------------------------------------------------------------------

pub mod proto {
    use std::fmt;

    /// Largest frame this implementation can produce or consume.
    ///
    /// Upstream uses 21 bytes (the size of a pointer-motion frame). The variable-length
    /// [`InputEvent::StateSync`] frame needs more, so the buffer is larger; every frame that
    /// upstream defines is still exactly as long as upstream defines it.
    pub const MAX_FRAME_SIZE: usize = 128;

    /// How many simultaneously pressed keys an [`InputEvent::StateSync`] frame can carry.
    pub const MAX_SYNC_KEYS: usize = 24;

    /// Build identification exchanged in the `Hello` frame. Upstream sends its git short commit
    /// here; this file sends a fixed tag so a peer can tell which implementation it talks to.
    pub const PROTOCOL_VERSION: [u8; 8] = *b"RI-00001";

    /// Linux evdev button codes, identical to upstream's `input_event::{BTN_*}`.
    pub const BTN_LEFT: u32 = 0x110;
    pub const BTN_RIGHT: u32 = 0x111;
    pub const BTN_MIDDLE: u32 = 0x112;
    pub const BTN_BACK: u32 = 0x113;
    pub const BTN_FORWARD: u32 = 0x114;

    /// Scroll axis indices used by upstream: 0 = vertical, 1 = horizontal.
    pub const AXIS_VERTICAL: u8 = 0;
    pub const AXIS_HORIZONTAL: u8 = 1;

    /// Position of the peer relative to this device. Only used for the `Enter` frame, which is kept
    /// for wire compatibility with upstream; this core does not do barrier detection.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    #[repr(u8)]
    pub enum Direction {
        Left = 0,
        #[default]
        Right = 1,
        Top = 2,
        Bottom = 3,
    }

    impl Direction {
        pub fn opposite(self) -> Self {
            match self {
                Direction::Left => Direction::Right,
                Direction::Right => Direction::Left,
                Direction::Top => Direction::Bottom,
                Direction::Bottom => Direction::Top,
            }
        }

        fn from_u8(v: u8) -> std::result::Result<Self, ProtocolError> {
            Ok(match v {
                0 => Direction::Left,
                1 => Direction::Right,
                2 => Direction::Top,
                3 => Direction::Bottom,
                other => return Err(ProtocolError::InvalidValue("direction", other as u32)),
            })
        }
    }

    impl fmt::Display for Direction {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let s = match self {
                Direction::Left => "left",
                Direction::Right => "right",
                Direction::Top => "top",
                Direction::Bottom => "bottom",
            };
            f.write_str(s)
        }
    }

    /// Why a capture device went away. Sent to the peer so it can release every key immediately
    /// instead of waiting for the watchdog.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum DisconnectReason {
        /// `stop_capture()` was called.
        CaptureStopped = 0,
        /// `disable_remote_input()` was called.
        ForwardingDisabled = 1,
        /// The local input device disappeared (unplugged, permission revoked).
        DeviceLost = 2,
        /// The local panic chord (release bind) was pressed.
        ReleaseBind = 3,
        /// The engine is shutting down.
        Shutdown = 4,
        /// The remote side asked us to stop.
        RemoteRequest = 5,
    }

    impl DisconnectReason {
        fn from_u8(v: u8) -> std::result::Result<Self, ProtocolError> {
            Ok(match v {
                0 => DisconnectReason::CaptureStopped,
                1 => DisconnectReason::ForwardingDisabled,
                2 => DisconnectReason::DeviceLost,
                3 => DisconnectReason::ReleaseBind,
                4 => DisconnectReason::Shutdown,
                5 => DisconnectReason::RemoteRequest,
                other => {
                    return Err(ProtocolError::InvalidValue("disconnect reason", other as u32))
                }
            })
        }
    }

    bitflags::bitflags! {
        /// X11-style modifier mask, exactly the bit layout upstream uses on the wire
        /// (`KeyboardEvent::Modifiers` carries these bits).
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct Modifiers: u32 {
            const SHIFT = 1 << 0;
            const LOCK = 1 << 1;
            const CONTROL = 1 << 2;
            const MOD1 = 1 << 3;
            const MOD2 = 1 << 4;
            const MOD3 = 1 << 5;
            const MOD4 = 1 << 6;
            const MOD5 = 1 << 7;
        }
    }

    /// A small, `Copy`, allocation-free set of evdev key codes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct KeySet {
        len: u8,
        keys: [u32; MAX_SYNC_KEYS],
    }

    impl Default for KeySet {
        fn default() -> Self {
            Self { len: 0, keys: [0; MAX_SYNC_KEYS] }
        }
    }

    impl KeySet {
        pub fn new() -> Self {
            Self::default()
        }

        /// Build from an iterator; keys beyond [`MAX_SYNC_KEYS`] are dropped, the caller learns
        /// this from [`KeySet::truncated`].
        pub fn from_iter(iter: impl IntoIterator<Item = u32>) -> Self {
            let mut set = Self::default();
            for key in iter {
                set.insert(key);
            }
            set
        }

        pub fn insert(&mut self, key: u32) {
            if self.contains(key) || (self.len as usize) >= MAX_SYNC_KEYS {
                return;
            }
            self.keys[self.len as usize] = key;
            self.len += 1;
        }

        pub fn contains(&self, key: u32) -> bool {
            self.keys[..self.len as usize].contains(&key)
        }

        pub fn len(&self) -> usize {
            self.len as usize
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// True if keys had to be dropped because the frame is full.
        pub fn truncated(&self, total: usize) -> bool {
            total > self.len as usize
        }

        pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
            self.keys[..self.len as usize].iter().copied()
        }
    }

    /// The unified, platform-neutral input event. This is the *only* thing that crosses the
    /// network; no OS event struct is ever serialised.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum InputEvent {
        KeyboardKeyDown { key: u32, time: u32 },
        KeyboardKeyUp { key: u32, time: u32 },
        MouseButtonDown { button: u32, time: u32 },
        MouseButtonUp { button: u32, time: u32 },
        /// Relative pointer motion in display points/pixels.
        MouseMove { dx: f64, dy: f64, time: u32 },
        /// Discrete wheel motion: 120 units = one notch (upstream's `AxisDiscrete120`).
        MouseWheel { axis: u8, delta120: i32 },
        /// High-resolution / touchpad scrolling in pixels (upstream's `Axis`).
        MouseScroll { axis: u8, pixels: f64, time: u32 },
        /// Full modifier state. `depressed`/`locked` use the [`Modifiers`] bit layout.
        ModifierState { depressed: u32, latched: u32, locked: u32, group: u32 },
        /// The local capture device disappeared; the receiver must release everything.
        DeviceDisconnect { reason: DisconnectReason },
        /// Authoritative input state of the sender, used to repair lost/reordered frames.
        StateSync { seq: u32, depressed: u32, locked: u32, buttons: u32, keys: KeySet },
    }

    impl InputEvent {
        /// Timestamp in milliseconds since the sender started capturing (0 if not applicable).
        pub fn time(&self) -> u32 {
            match self {
                InputEvent::KeyboardKeyDown { time, .. }
                | InputEvent::KeyboardKeyUp { time, .. }
                | InputEvent::MouseButtonDown { time, .. }
                | InputEvent::MouseButtonUp { time, .. }
                | InputEvent::MouseMove { time, .. }
                | InputEvent::MouseScroll { time, .. } => *time,
                _ => 0,
            }
        }

        pub fn is_key_down(&self) -> bool {
            matches!(self, InputEvent::KeyboardKeyDown { .. })
        }

        pub fn is_key_up(&self) -> bool {
            matches!(self, InputEvent::KeyboardKeyUp { .. })
        }
    }

    impl fmt::Display for InputEvent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                InputEvent::KeyboardKeyDown { key, .. } => write!(f, "key_down({key})"),
                InputEvent::KeyboardKeyUp { key, .. } => write!(f, "key_up({key})"),
                InputEvent::MouseButtonDown { button, .. } => write!(f, "btn_down({button:#x})"),
                InputEvent::MouseButtonUp { button, .. } => write!(f, "btn_up({button:#x})"),
                InputEvent::MouseMove { dx, dy, .. } => write!(f, "move({dx},{dy})"),
                InputEvent::MouseWheel { axis, delta120 } => write!(f, "wheel({axis},{delta120})"),
                InputEvent::MouseScroll { axis, pixels, .. } => {
                    write!(f, "scroll({axis},{pixels})")
                }
                InputEvent::ModifierState { depressed, locked, .. } => {
                    write!(f, "mods(dep={depressed:#x},lock={locked:#x})")
                }
                InputEvent::DeviceDisconnect { reason } => write!(f, "disconnect({reason:?})"),
                InputEvent::StateSync { seq, keys, .. } => {
                    write!(f, "sync(seq={seq},keys={})", keys.len())
                }
            }
        }
    }

    /// Everything that can be sent over a connection.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum ProtoEvent {
        /// An input event.
        Input(InputEvent),
        /// "my cursor entered your region": the receiver answers with [`ProtoEvent::Ack`].
        Enter(Direction),
        /// "my cursor left your region": the receiver releases every key of that peer.
        Leave(u32),
        /// Acknowledge an `Enter`/`Leave`; also the handshake completion signal.
        Ack(u32),
        /// Liveness probe, answered with [`ProtoEvent::Pong`].
        Ping,
        /// Liveness answer; `true` means the peer is able and willing to inject input.
        Pong(bool),
        /// Build identification, sent once after the DTLS handshake and echoed back.
        Hello([u8; 8]),
    }

    impl fmt::Display for ProtoEvent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ProtoEvent::Input(e) => write!(f, "{e}"),
                ProtoEvent::Enter(d) => write!(f, "enter({d})"),
                ProtoEvent::Leave(s) => write!(f, "leave({s})"),
                ProtoEvent::Ack(s) => write!(f, "ack({s})"),
                ProtoEvent::Ping => f.write_str("ping"),
                ProtoEvent::Pong(alive) => write!(f, "pong({alive})"),
                ProtoEvent::Hello(v) => write!(f, "hello({})", String::from_utf8_lossy(v)),
            }
        }
    }

    /// Frame ids. 0-11 are upstream's ids and keep upstream's byte layout.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum FrameType {
        PointerMotion = 0,
        PointerButton = 1,
        PointerAxis = 2,
        PointerAxisValue120 = 3,
        KeyboardKey = 4,
        KeyboardModifiers = 5,
        Ping = 6,
        Pong = 7,
        Enter = 8,
        Leave = 9,
        Ack = 10,
        Hello = 11,
        /// Extension: capture device disappeared.
        DeviceDisconnect = 12,
        /// Extension: authoritative state snapshot.
        StateSync = 13,
    }

    impl FrameType {
        fn from_u8(v: u8) -> std::result::Result<Self, ProtocolError> {
            Ok(match v {
                0 => FrameType::PointerMotion,
                1 => FrameType::PointerButton,
                2 => FrameType::PointerAxis,
                3 => FrameType::PointerAxisValue120,
                4 => FrameType::KeyboardKey,
                5 => FrameType::KeyboardModifiers,
                6 => FrameType::Ping,
                7 => FrameType::Pong,
                8 => FrameType::Enter,
                9 => FrameType::Leave,
                10 => FrameType::Ack,
                11 => FrameType::Hello,
                12 => FrameType::DeviceDisconnect,
                13 => FrameType::StateSync,
                other => return Err(ProtocolError::UnknownFrame(other)),
            })
        }
    }

    /// Only the two axes upstream defines are legal on the wire.
    fn axis_index(axis: u8) -> std::result::Result<u8, ProtocolError> {
        match axis {
            AXIS_VERTICAL | AXIS_HORIZONTAL => Ok(axis),
            other => Err(ProtocolError::InvalidValue("scroll axis", other as u32)),
        }
    }

    #[derive(Debug, thiserror::Error, PartialEq)]
    pub enum ProtocolError {
        #[error("frame truncated: needed {needed} bytes, got {got}")]
        Truncated { needed: usize, got: usize },
        #[error("unknown frame type {0}")]
        UnknownFrame(u8),
        #[error("invalid {0} value {1}")]
        InvalidValue(&'static str, u32),
        #[error("frame of {0} bytes exceeds MAX_FRAME_SIZE")]
        TooLarge(usize),
    }

    // -- codec ---------------------------------------------------------------------------------

    struct Writer<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }

    impl<'a> Writer<'a> {
        fn new(buf: &'a mut [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn u8(&mut self, v: u8) {
            self.buf[self.pos] = v;
            self.pos += 1;
        }

        fn u32(&mut self, v: u32) {
            self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_be_bytes());
            self.pos += 4;
        }

        fn i32(&mut self, v: i32) {
            self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_be_bytes());
            self.pos += 4;
        }

        fn f64(&mut self, v: f64) {
            self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_be_bytes());
            self.pos += 8;
        }
    }

    struct Reader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], ProtocolError> {
            if self.pos + n > self.buf.len() {
                return Err(ProtocolError::Truncated { needed: self.pos + n, got: self.buf.len() });
            }
            let s = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Ok(s)
        }

        fn u8(&mut self) -> std::result::Result<u8, ProtocolError> {
            Ok(self.take(1)?[0])
        }

        fn u32(&mut self) -> std::result::Result<u32, ProtocolError> {
            let b = self.take(4)?;
            Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }

        fn i32(&mut self) -> std::result::Result<i32, ProtocolError> {
            let b = self.take(4)?;
            Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }

        fn f64(&mut self) -> std::result::Result<f64, ProtocolError> {
            let b = self.take(8)?;
            Ok(f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        }
    }

    /// Serialise into `buf`, returning the number of bytes written.
    ///
    /// Big-endian, fixed layout, no length prefix: one datagram = one frame, exactly like upstream.
    pub fn encode(event: &ProtoEvent, buf: &mut [u8; MAX_FRAME_SIZE]) -> usize {
        let mut w = Writer::new(&mut buf[..]);
        match event {
            ProtoEvent::Input(input) => match input {
                InputEvent::MouseMove { dx, dy, time } => {
                    w.u8(FrameType::PointerMotion as u8);
                    w.u32(*time);
                    w.f64(*dx);
                    w.f64(*dy);
                }
                InputEvent::MouseButtonDown { button, time }
                | InputEvent::MouseButtonUp { button, time } => {
                    let state = matches!(input, InputEvent::MouseButtonDown { .. }) as u32;
                    w.u8(FrameType::PointerButton as u8);
                    w.u32(*time);
                    w.u32(*button);
                    w.u32(state);
                }
                InputEvent::MouseScroll { axis, pixels, time } => {
                    w.u8(FrameType::PointerAxis as u8);
                    w.u32(*time);
                    w.u8(*axis);
                    w.f64(*pixels);
                }
                InputEvent::MouseWheel { axis, delta120 } => {
                    w.u8(FrameType::PointerAxisValue120 as u8);
                    w.u8(*axis);
                    w.i32(*delta120);
                }
                InputEvent::KeyboardKeyDown { key, time }
                | InputEvent::KeyboardKeyUp { key, time } => {
                    let state = matches!(input, InputEvent::KeyboardKeyDown { .. }) as u8;
                    w.u8(FrameType::KeyboardKey as u8);
                    w.u32(*time);
                    w.u32(*key);
                    w.u8(state);
                }
                InputEvent::ModifierState { depressed, latched, locked, group } => {
                    w.u8(FrameType::KeyboardModifiers as u8);
                    w.u32(*depressed);
                    w.u32(*latched);
                    w.u32(*locked);
                    w.u32(*group);
                }
                InputEvent::DeviceDisconnect { reason } => {
                    w.u8(FrameType::DeviceDisconnect as u8);
                    w.u8(*reason as u8);
                }
                InputEvent::StateSync { seq, depressed, locked, buttons, keys } => {
                    w.u8(FrameType::StateSync as u8);
                    w.u32(*seq);
                    w.u32(*depressed);
                    w.u32(*locked);
                    w.u32(*buttons);
                    w.u8(keys.len() as u8);
                    for key in keys.iter() {
                        w.u32(key);
                    }
                }
            },
            ProtoEvent::Enter(dir) => {
                w.u8(FrameType::Enter as u8);
                w.u8(*dir as u8);
            }
            ProtoEvent::Leave(serial) => {
                w.u8(FrameType::Leave as u8);
                w.u32(*serial);
            }
            ProtoEvent::Ack(serial) => {
                w.u8(FrameType::Ack as u8);
                w.u32(*serial);
            }
            ProtoEvent::Ping => w.u8(FrameType::Ping as u8),
            ProtoEvent::Pong(alive) => {
                w.u8(FrameType::Pong as u8);
                w.u8(*alive as u8);
            }
            ProtoEvent::Hello(version) => {
                w.u8(FrameType::Hello as u8);
                for b in version {
                    w.u8(*b);
                }
            }
        }
        w.pos
    }

    /// Parse a datagram. Undecodable frames yield an error and must be skipped *without* dropping
    /// the connection (forward compatibility, as upstream does).
    pub fn decode(buf: &[u8]) -> std::result::Result<ProtoEvent, ProtocolError> {
        if buf.len() > MAX_FRAME_SIZE {
            return Err(ProtocolError::TooLarge(buf.len()));
        }
        let mut r = Reader::new(buf);
        let frame = FrameType::from_u8(r.u8()?)?;
        Ok(match frame {
            FrameType::PointerMotion => ProtoEvent::Input(InputEvent::MouseMove {
                time: r.u32()?,
                dx: r.f64()?,
                dy: r.f64()?,
            }),
            FrameType::PointerButton => {
                let time = r.u32()?;
                let button = r.u32()?;
                let state = r.u32()?;
                ProtoEvent::Input(if state == 0 {
                    InputEvent::MouseButtonUp { button, time }
                } else {
                    InputEvent::MouseButtonDown { button, time }
                })
            }
            FrameType::PointerAxis => {
                let time = r.u32()?;
                let axis = axis_index(r.u8()?)?;
                ProtoEvent::Input(InputEvent::MouseScroll { time, axis, pixels: r.f64()? })
            }
            FrameType::PointerAxisValue120 => {
                let axis = axis_index(r.u8()?)?;
                ProtoEvent::Input(InputEvent::MouseWheel { axis, delta120: r.i32()? })
            }
            FrameType::KeyboardKey => {
                let time = r.u32()?;
                let key = r.u32()?;
                let state = r.u8()?;
                ProtoEvent::Input(if state == 0 {
                    InputEvent::KeyboardKeyUp { key, time }
                } else {
                    InputEvent::KeyboardKeyDown { key, time }
                })
            }
            FrameType::KeyboardModifiers => ProtoEvent::Input(InputEvent::ModifierState {
                depressed: r.u32()?,
                latched: r.u32()?,
                locked: r.u32()?,
                group: r.u32()?,
            }),
            FrameType::Ping => ProtoEvent::Ping,
            FrameType::Pong => ProtoEvent::Pong(r.u8()? != 0),
            FrameType::Enter => ProtoEvent::Enter(Direction::from_u8(r.u8()?)?),
            FrameType::Leave => ProtoEvent::Leave(r.u32()?),
            FrameType::Ack => ProtoEvent::Ack(r.u32()?),
            FrameType::Hello => {
                let mut v = [0u8; 8];
                for b in v.iter_mut() {
                    *b = r.u8()?;
                }
                ProtoEvent::Hello(v)
            }
            FrameType::DeviceDisconnect => ProtoEvent::Input(InputEvent::DeviceDisconnect {
                reason: DisconnectReason::from_u8(r.u8()?)?,
            }),
            FrameType::StateSync => {
                let seq = r.u32()?;
                let depressed = r.u32()?;
                let locked = r.u32()?;
                let buttons = r.u32()?;
                let count = r.u8()? as usize;
                if count > MAX_SYNC_KEYS {
                    return Err(ProtocolError::InvalidValue("sync key count", count as u32));
                }
                let mut keys = KeySet::new();
                for _ in 0..count {
                    keys.insert(r.u32()?);
                }
                ProtoEvent::Input(InputEvent::StateSync { seq, depressed, locked, buttons, keys })
            }
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Key map: Linux evdev is the canonical wire representation (as in upstream), macOS converts
// ---------------------------------------------------------------------------------------------

pub mod keymap {
    use super::proto::{Modifiers, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT};

    /// Linux evdev key codes (subset; the full table lives in `input-event/src/scancode.rs`).
    pub const KEY_ESC: u32 = 1;
    pub const KEY_LEFTCTRL: u32 = 29;
    pub const KEY_LEFTSHIFT: u32 = 42;
    pub const KEY_RIGHTSHIFT: u32 = 54;
    pub const KEY_LEFTALT: u32 = 56;
    pub const KEY_CAPSLOCK: u32 = 58;
    pub const KEY_NUMLOCK: u32 = 69;
    pub const KEY_SCROLLLOCK: u32 = 70;
    pub const KEY_RIGHTCTRL: u32 = 97;
    pub const KEY_SYSRQ: u32 = 99;
    pub const KEY_RIGHTALT: u32 = 100;
    pub const KEY_PAUSE: u32 = 119;
    pub const KEY_LEFTMETA: u32 = 125;
    pub const KEY_RIGHTMETA: u32 = 126;

    /// First button code; everything in `BTN_MISC..0x160` is a button, not a key.
    pub const BTN_MISC: u32 = 0x100;

    /// Keys macOS has no equivalent for; upstream maps them onto F13/F14/F15, the convention every
    /// remote-desktop tool uses.
    #[cfg(target_os = "macos")]
    pub const MAC_VK_F13: u16 = 0x69;
    #[cfg(target_os = "macos")]
    pub const MAC_VK_F14: u16 = 0x6B;
    #[cfg(target_os = "macos")]
    pub const MAC_VK_F15: u16 = 0x71;

    /// Arrow keys carry `NumericPad | SecondaryFn` on real macOS keyboards; hotkey matchers check
    /// those flags (upstream does the same in `input-emulation/src/macos.rs`).
    #[cfg(target_os = "macos")]
    pub fn is_mac_arrow_key(vk: u16) -> bool {
        matches!(vk, 0x7B | 0x7C | 0x7D | 0x7E)
    }

    /// Is this evdev code a mouse button?
    pub fn is_button(code: u32) -> bool {
        (BTN_MISC..0x160).contains(&code)
    }

    /// Modifier bit contributed while the key is held.
    pub fn held_mask(key: u32) -> Modifiers {
        match key {
            KEY_LEFTSHIFT | KEY_RIGHTSHIFT => Modifiers::SHIFT,
            KEY_LEFTCTRL | KEY_RIGHTCTRL => Modifiers::CONTROL,
            KEY_LEFTALT | KEY_RIGHTALT => Modifiers::MOD1,
            KEY_LEFTMETA | KEY_RIGHTMETA => Modifiers::MOD4,
            _ => Modifiers::empty(),
        }
    }

    /// Lock bit toggled by a locking key (Caps Lock / Num Lock / Scroll Lock).
    pub fn lock_mask(key: u32) -> Modifiers {
        match key {
            KEY_CAPSLOCK => Modifiers::LOCK,
            KEY_NUMLOCK => Modifiers::MOD2,
            KEY_SCROLLLOCK => Modifiers::MOD3,
            _ => Modifiers::empty(),
        }
    }

    pub fn is_modifier(key: u32) -> bool {
        !held_mask(key).is_empty() || !lock_mask(key).is_empty()
    }

    /// Tracks X11-style modifier state from evdev key transitions.
    ///
    /// Ported from `input-emulation/src/wlroots.rs` (`XMods::update_by_key_event`) and
    /// `input-emulation/src/macos.rs` (`update_modifiers`): a held modifier is set on press and
    /// cleared on release, a locking key toggles on press and ignores its release. That asymmetry
    /// is what macOS itself does, and it keeps the two sides of a connection consistent.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct ModifierTracker {
        mask: Modifiers,
    }

    impl ModifierTracker {
        pub fn new() -> Self {
            Self { mask: Modifiers::empty() }
        }

        pub fn mask(&self) -> Modifiers {
            self.mask
        }

        /// Modifiers currently *held* (without the lock bits).
        pub fn pressed(&self) -> Modifiers {
            self.mask & (Modifiers::SHIFT | Modifiers::CONTROL | Modifiers::MOD1 | Modifiers::MOD4)
        }

        /// Lock bits only.
        pub fn locks(&self) -> Modifiers {
            self.mask & (Modifiers::LOCK | Modifiers::MOD2 | Modifiers::MOD3)
        }

        /// Apply a key transition. Returns true if the state changed.
        pub fn update(&mut self, key: u32, down: bool) -> bool {
            let held = held_mask(key);
            let lock = lock_mask(key);
            if held.is_empty() && lock.is_empty() {
                return false;
            }
            let before = self.mask;
            if down {
                self.mask |= held;
                if !lock.is_empty() {
                    self.mask.toggle(lock);
                }
            } else {
                self.mask.remove(held);
            }
            self.mask != before
        }

        /// Replace the whole mask from a `ModifierState` event (peer is authoritative).
        pub fn set(&mut self, depressed: u32, locked: u32) {
            self.mask = Modifiers::from_bits_truncate(depressed)
                | Modifiers::from_bits_truncate(locked & Modifiers::LOCK.bits());
        }

        pub fn reset(&mut self) {
            self.mask = Modifiers::empty();
        }
    }

    // -- macOS key-code conversion -------------------------------------------------------------

    /// macOS virtual key code → evdev code. `None` for keys macOS has but evdev does not (media
    /// keys, brightness, ...); the caller drops those and logs it.
    #[cfg(target_os = "macos")]
    pub fn mac_to_evdev(vk: u16) -> Option<u32> {
        use keycode::{KeyMap, KeyMapping};
        let map = KeyMap::from_key_mapping(KeyMapping::Mac(vk)).ok()?;
        // The Chromium-derived table stores "no equivalent" as 0 for some entries.
        if map.evdev == 0 {
            None
        } else {
            Some(map.evdev as u32)
        }
    }

    /// evdev code → macOS virtual key code, including upstream's SysRq/ScrollLock/Pause →
    /// F13/F14/F15 fallback.
    #[cfg(target_os = "macos")]
    pub fn evdev_to_mac(key: u32) -> Option<u16> {
        use keycode::{KeyMap, KeyMapping};
        match key {
            KEY_SYSRQ => return Some(MAC_VK_F13),
            KEY_SCROLLLOCK => return Some(MAC_VK_F14),
            KEY_PAUSE => return Some(MAC_VK_F15),
            _ => {}
        }
        if key > u16::MAX as u32 {
            return None;
        }
        let map = KeyMap::from_key_mapping(KeyMapping::Evdev(key as u16)).ok()?;
        Some(map.mac)
    }

    /// Human readable name for logging (mirrors upstream's `Display` impls).
    pub fn button_name(button: u32) -> &'static str {
        match button {
            BTN_LEFT => "left",
            BTN_RIGHT => "right",
            BTN_MIDDLE => "middle",
            0x113 => "back",
            0x114 => "forward",
            _ => "other",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Transport: UDP + DTLS, the design upstream uses (see src/connect.rs and src/listen.rs)
//
// Why DTLS over UDP (upstream's choice, kept here):
//   + one datagram per input event: no head-of-line blocking, no Nagle, minimal latency
//   + mandatory encryption + authentication of both ends (self-signed cert + fingerprint pinning)
//   + the handshake also gives a cheap liveness/identity check
//   - no delivery guarantee: a lost key-up is possible (mitigated by StateSync, see the engine)
//   - no ordering guarantee at the record layer for application data
//   - UDP can be blocked by restrictive firewalls; DTLS adds ~1 RTT of handshake latency
// ---------------------------------------------------------------------------------------------

pub mod transport {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use tokio::net::UdpSocket;
    use webrtc_dtls::{
        config::{ClientAuthType, Config as DtlsConfig, ExtendedMasterSecretType},
        conn::DTLSConn,
        crypto::Certificate,
        listener::listen,
    };
    use webrtc_util::{conn::Listener, Conn};

    pub type ArcConn = Arc<dyn Conn + Send + Sync>;
    pub type BoxedListener = Box<dyn Listener + Send + Sync>;

    /// SHA-256 over the DER certificate; the identity of a peer.
    pub type Fingerprint = [u8; 32];

    pub type VerifyFn = Arc<
        dyn Fn(&[Vec<u8>], &[rustls::pki_types::CertificateDer<'static>]) -> std::result::Result<(), webrtc_dtls::Error>
            + Send
            + Sync,
    >;

    pub fn fingerprint(der: &[u8]) -> Fingerprint {
        let mut hasher = Sha256::new();
        hasher.update(der);
        hasher.finalize().into()
    }

    pub fn fingerprint_hex(fp: &Fingerprint) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(64);
        for b in fp {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn parse_fingerprint_hex(hex: &str) -> Option<Fingerprint> {
        let clean: String = hex
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '-' | '\n' | '\t'))
            .collect::<String>()
            .to_ascii_lowercase();
        if clean.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            out[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(out)
    }

    /// Self-signed identity. Upstream generates one certificate per installation
    /// (`src/crypto.rs`) and authenticates peers by its fingerprint.
    pub struct Identity {
        pub cert: Certificate,
        pub fingerprint: Fingerprint,
    }

    impl Identity {
        pub fn generate() -> Result<Self> {
            let cert = Certificate::generate_self_signed(vec!["remote-input".to_string()])
                .map_err(|e| InputError::Network(format!("certificate generation failed: {e}")))?;
            let der = cert
                .certificate
                .first()
                .ok_or_else(|| InputError::Network("generated certificate is empty".into()))?;
            let fingerprint = fingerprint(der);
            Ok(Self { cert, fingerprint })
        }
    }

    /// Dial one address and complete the DTLS handshake.
    pub async fn dial(
        addr: SocketAddr,
        cert: Certificate,
        expected_peer: Option<Fingerprint>,
        timeout: Duration,
    ) -> Result<ArcConn> {
        let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        sock.connect(addr).await?;

        let verify: Option<VerifyFn> = expected_peer.map(|expected| {
            Arc::new(
                move |certs: &[Vec<u8>],
                      _chain: &[rustls::pki_types::CertificateDer<'static>]|
                      -> std::result::Result<(), webrtc_dtls::Error> {
                    match certs.first() {
                        Some(der) if fingerprint(der) == expected => Ok(()),
                        Some(_) => Err(webrtc_dtls::Error::ErrVerifyDataMismatch),
                        None => Err(webrtc_dtls::Error::ErrInvalidCertificate),
                    }
                },
            ) as VerifyFn
        });

        let cfg = DtlsConfig {
            certificates: vec![cert],
            server_name: "remote-input".to_owned(),
            // As upstream: no CA validation. If the caller pinned a fingerprint,
            // `verify_peer_certificate` enforces it instead.
            insecure_skip_verify: true,
            extended_master_secret: ExtendedMasterSecretType::Require,
            verify_peer_certificate: verify,
            ..Default::default()
        };

        match tokio::time::timeout(timeout, DTLSConn::new(sock, cfg, true, None)).await {
            Ok(Ok(conn)) => Ok(Arc::new(conn)),
            Ok(Err(e)) => Err(InputError::Network(format!(
                "DTLS handshake with {addr} failed: {e}"
            ))),
            Err(_) => Err(InputError::ConnectTimeout { addr }),
        }
    }

    /// Try several addresses in parallel and return the first handshake that succeeds
    /// (upstream's `connect_any`).
    pub async fn dial_any(
        addrs: &[SocketAddr],
        cert: Certificate,
        expected_peer: Option<Fingerprint>,
        timeout: Duration,
    ) -> Result<(ArcConn, SocketAddr)> {
        if addrs.is_empty() {
            return Err(InputError::Network("no address to connect to".into()));
        }
        if addrs.len() == 1 {
            let addr = addrs[0];
            let conn = dial(addr, cert, expected_peer, timeout).await?;
            return Ok((conn, addr));
        }

        let mut set = tokio::task::JoinSet::new();
        for addr in addrs.iter().copied() {
            let cert = cert.clone();
            set.spawn(async move { (addr, dial(addr, cert, expected_peer, timeout).await) });
        }
        let mut last_err = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((addr, Ok(conn))) => {
                    set.abort_all();
                    return Ok((conn, addr));
                }
                Ok((addr, Err(e))) => {
                    log::debug!("dial {addr} failed: {e}");
                    last_err = Some(e);
                }
                Err(e) => last_err = Some(InputError::Network(format!("dial task failed: {e}"))),
            }
        }
        Err(last_err.unwrap_or_else(|| InputError::Network("no address reachable".into())))
    }

    /// A bound DTLS listener plus the queue of rejected fingerprints, so the caller can tell the
    /// user *which* unknown peer tried to connect (upstream's `ListenEvent::Rejected`).
    pub struct Bound {
        pub listener: BoxedListener,
        pub port: u16,
        pub rejected: Arc<std::sync::Mutex<VecDeque<Fingerprint>>>,
    }

    /// Bind a DTLS listener that requires a client certificate and checks it against `authorized`
    /// (empty set + `allow_any == false` rejects everyone).
    pub async fn bind(
        port: u16,
        cert: Certificate,
        authorized: Arc<RwLock<HashSet<Fingerprint>>>,
        allow_any: bool,
    ) -> Result<Bound> {
        let rejected: Arc<std::sync::Mutex<VecDeque<Fingerprint>>> = Default::default();
        let rejected_cb = rejected.clone();

        let verify: VerifyFn = Arc::new(
            move |certs: &[Vec<u8>],
                  _chain: &[rustls::pki_types::CertificateDer<'static>]|
                  -> std::result::Result<(), webrtc_dtls::Error> {
                let Some(der) = certs.first() else {
                    return Err(webrtc_dtls::Error::ErrInvalidCertificate);
                };
                let fp = fingerprint(der);
                if allow_any {
                    log::warn!(
                        "accepting peer {} without authorization (allow_any_peer = true)",
                        fingerprint_hex(&fp)
                    );
                    return Ok(());
                }
                let allowed = authorized.read().map(|set| set.contains(&fp)).unwrap_or(false);
                if allowed {
                    Ok(())
                } else {
                    log::warn!("rejecting unauthorized peer {}", fingerprint_hex(&fp));
                    if let Ok(mut q) = rejected_cb.lock() {
                        q.push_back(fp);
                    }
                    // There is no "soft" rejection in DTLS: the handshake must fail.
                    Err(webrtc_dtls::Error::ErrVerifyDataMismatch)
                }
            },
        );

        let cfg = DtlsConfig {
            certificates: vec![cert],
            extended_master_secret: ExtendedMasterSecretType::Require,
            client_auth: ClientAuthType::RequireAnyClientCert,
            verify_peer_certificate: Some(verify),
            ..Default::default()
        };

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener: BoxedListener = Box::new(
            listen(addr, cfg)
                .await
                .map_err(|e| InputError::Network(format!("cannot bind UDP port {port}: {e}")))?,
        );
        let bound_port = listener.addr().await.map(|a| a.port()).unwrap_or(port);
        Ok(Bound { listener, port: bound_port, rejected })
    }
}

// ---------------------------------------------------------------------------------------------
// macOS input capture: CGEventTap
//
// Ported from input-capture/src/macos.rs. Kept: session tap at head-insert position with `Default`
// options, the swallow decision, `FlagsChanged` → modifier mapping, scroll-wheel natural-scroll
// correction, tap-disabled recovery, local-event suppression interval and the private
// `SetsCursorInBackground` property. Dropped: barrier/display-bounds logic (this core is driven by
// the API instead of by screen edges) and the display-reconfiguration callback.
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub mod mac_capture {
    use super::keymap;
    use super::proto::{DisconnectReason, InputEvent, Modifiers};
    use super::*;

    use core_foundation::base::{CFRelease, TCFType, kCFAllocatorDefault};
    use core_foundation::date::CFTimeInterval;
    use core_foundation::runloop::CFRunLoop;
    use core_foundation::string::{CFStringCreateWithCString, CFStringRef, kCFStringEncodingUTF8};
    use core_graphics::base::{CGError, kCGErrorSuccess};
    use core_graphics::display::{CGDisplay, CGPoint};
    use core_graphics::event::{
        CGEvent, CGEventField, CGEventFlags, CGEventTap, CGEventTapLocation, CGEventTapOptions,
        CGEventTapPlacement, CGEventTapProxy, CGEventType, CallbackResult, EventField,
    };
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
    use std::ffi::{CString, c_char};
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use std::thread::JoinHandle;

    /// `isDirectionInvertedFromDevice`: non-zero when "Natural Scrolling" is active.
    const DIRECTION_INVERTED_FROM_DEVICE: CGEventField = 137;

    /// macOS scroll-wheel deltas are line based; upstream maps one line to 3 "notches" of 120.
    const LINES_PER_STEP: i32 = 3;
    const V120_STEPS_PER_LINE: i32 = 120 / LINES_PER_STEP;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn CGSSetConnectionProperty(
            cid: CGSConnectionID,
            target_cid: CGSConnectionID,
            key: CFStringRef,
            value: core_foundation::number::CFBooleanRef,
        ) -> CGError;
        fn _CGSDefaultConnection() -> CGSConnectionID;
        fn AXIsProcessTrusted() -> bool;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceSetLocalEventsSuppressionInterval(
            event_source: CGEventSource,
            seconds: CFTimeInterval,
        );
        fn CGPreflightListenEventAccess() -> bool;
        /// Apple-documented recovery for `kCGEventTapDisabledByTimeout`.
        fn CGEventTapEnable(tap: *mut std::ffi::c_void, enable: bool);
    }

    type CGSConnectionID = u32;

    /// State shared between the tap callback and the control side.
    #[derive(Default)]
    struct TapState {
        /// Where the (hidden) cursor is pinned while forwarding.
        anchor: Option<CGPoint>,
        cursor_hidden: bool,
        /// Modifier mask as last reported to the peer.
        mods: Modifiers,
    }

    /// Handle to a running event tap.
    pub struct MacCapture {
        run_loop: CFRunLoop,
        thread: Option<JoinHandle<()>>,
        forwarding: Arc<AtomicBool>,
        state: Arc<Mutex<TapState>>,
    }

    impl MacCapture {
        /// Start the tap. Returns an error (never a fake success) if Accessibility or Input
        /// Monitoring has not been granted.
        pub fn start(tx: mpsc::Sender<InputEvent>, forwarding: Arc<AtomicBool>) -> Result<Self> {
            // Both permissions are checked (and, on first launch, registered with TCC) even if the
            // first one already failed: otherwise TCC only shows the second prompt on the next
            // launch.
            let accessibility = unsafe { AXIsProcessTrusted() };
            let input_monitoring = unsafe { CGPreflightListenEventAccess() };
            if !accessibility {
                return Err(InputError::CapturePermission(
                    "Accessibility access is required (System Settings → Privacy & Security → \
                     Accessibility); the event tap cannot see keyboard or mouse input without it."
                        .into(),
                ));
            }
            if !input_monitoring {
                return Err(InputError::CapturePermission(
                    "Input Monitoring access is required (System Settings → Privacy & Security → \
                     Input Monitoring)."
                        .into(),
                ));
            }

            unsafe { configure_cf_settings() };

            let state = Arc::new(Mutex::new(TapState::default()));
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<CFRunLoop>>();

            let thread_state = state.clone();
            let thread_forwarding = forwarding.clone();
            let thread = std::thread::Builder::new()
                .name("remote-input-tap".into())
                .spawn(move || tap_thread(tx, thread_forwarding, thread_state, ready_tx))?;

            let run_loop = ready_rx
                .recv()
                .map_err(|_| InputError::Capture("event tap thread died during setup".into()))??;

            Ok(Self { run_loop, thread: Some(thread), forwarding, state })
        }

        /// Enable/disable swallowing of local events. When disabled the tap keeps running but
        /// returns every event to the system, so local input is unaffected (upstream's
        /// pass-through state).
        pub fn set_forwarding(&self, on: bool) {
            self.forwarding.store(on, Ordering::SeqCst);
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.anchor = None; // captured on the next motion event
            if !on && st.cursor_hidden {
                let _ = CGDisplay::show_cursor(&CGDisplay::main());
                st.cursor_hidden = false;
            }
        }

        pub fn stop(mut self) {
            self.set_forwarding(false);
            self.run_loop.stop();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn tap_thread(
        tx: mpsc::Sender<InputEvent>,
        forwarding: Arc<AtomicBool>,
        state: Arc<Mutex<TapState>>,
        ready: std::sync::mpsc::Sender<Result<CFRunLoop>>,
    ) {
        let port_slot: Arc<OnceLock<usize>> = Arc::new(OnceLock::new());
        let tap = match create_tap(tx, forwarding, state, port_slot.clone()) {
            Ok(tap) => tap,
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
        // Store the mach port so the callback can re-enable the tap after a timeout disable.
        let _ = port_slot.set(tap.mach_port().as_concrete_TypeRef() as usize);

        let run_loop = CFRunLoop::get_current();
        if ready.send(Ok(run_loop.clone())).is_err() {
            return;
        }
        log::debug!("event tap running");
        CFRunLoop::run_current();
        log::debug!("event tap thread exiting");
        drop(tap);
    }

    fn create_tap(
        tx: mpsc::Sender<InputEvent>,
        forwarding: Arc<AtomicBool>,
        state: Arc<Mutex<TapState>>,
        port_slot: Arc<OnceLock<usize>>,
    ) -> Result<CGEventTap<'static>> {
        let events: Vec<CGEventType> = vec![
            CGEventType::LeftMouseDown,
            CGEventType::LeftMouseUp,
            CGEventType::RightMouseDown,
            CGEventType::RightMouseUp,
            CGEventType::OtherMouseDown,
            CGEventType::OtherMouseUp,
            CGEventType::MouseMoved,
            CGEventType::LeftMouseDragged,
            CGEventType::RightMouseDragged,
            CGEventType::OtherMouseDragged,
            CGEventType::ScrollWheel,
            CGEventType::KeyDown,
            CGEventType::KeyUp,
            CGEventType::FlagsChanged,
        ];

        let callback =
            move |_proxy: CGEventTapProxy, event_type: CGEventType, ev: &CGEvent| -> CallbackResult {
                // Tap lifetime problems arrive regardless of the forwarding state.
                match event_type {
                    CGEventType::TapDisabledByTimeout => {
                        // The kernel disables the tap if a callback takes longer than ~1 s. This
                        // is recoverable: re-enable in place and keep the state (as upstream).
                        if let Some(&port) = port_slot.get() {
                            log::warn!("event tap disabled by timeout - re-enabling");
                            unsafe { CGEventTapEnable(port as *mut std::ffi::c_void, true) };
                        } else {
                            log::error!("event tap disabled by timeout, no mach port to re-enable");
                        }
                        return CallbackResult::Keep;
                    }
                    CGEventType::TapDisabledByUserInput => {
                        // Secure input mode, revoked permission, or monitoring switched off. Not
                        // recoverable: drop capture state, release the peer, tell the engine.
                        log::error!("event tap disabled by user input - capture is dead");
                        {
                            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
                            if st.cursor_hidden {
                                let _ = CGDisplay::show_cursor(&CGDisplay::main());
                                st.cursor_hidden = false;
                            }
                        }
                        forwarding.store(false, Ordering::SeqCst);
                        let _ = tx.blocking_send(InputEvent::DeviceDisconnect {
                            reason: DisconnectReason::DeviceLost,
                        });
                        return CallbackResult::Keep;
                    }
                    _ => {}
                }

                if !forwarding.load(Ordering::Relaxed) {
                    // Passive monitoring: let the system have the event untouched.
                    return CallbackResult::Keep;
                }

                let mut out = EventBuf::new();
                let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
                translate(event_type, ev, &mut st, &mut out);

                // Keep the cursor where it was; otherwise the pointer runs off the screen while it
                // is "on the other machine".
                if matches!(
                    event_type,
                    CGEventType::MouseMoved
                        | CGEventType::LeftMouseDragged
                        | CGEventType::RightMouseDragged
                        | CGEventType::OtherMouseDragged
                ) {
                    pin_cursor(&mut st, ev);
                }

                if out.is_empty() {
                    // Nothing translatable (e.g. an unmapped media key): still swallow it, the
                    // user is typing on the other machine.
                    ev.set_type(CGEventType::Null);
                    return CallbackResult::Drop;
                }

                for event in out.iter() {
                    // Key and button events must never be dropped, motion may be.
                    let lossless = !matches!(
                        event,
                        InputEvent::MouseMove { .. } | InputEvent::MouseScroll { .. }
                    );
                    if lossless {
                        if tx.blocking_send(*event).is_err() {
                            log::debug!("capture channel closed");
                            return CallbackResult::Keep;
                        }
                    } else if tx.try_send(*event).is_err() {
                        log::trace!("capture channel full, dropping {event}");
                    }
                }

                // Marking the event as Null makes CoreGraphics forget it even though `Drop` is
                // only advisory (upstream does exactly this).
                ev.set_type(CGEventType::Null);
                CallbackResult::Drop
            };

        CGEventTap::new(
            CGEventTapLocation::Session,
            CGEventTapPlacement::HeadInsertEventTap,
            CGEventTapOptions::Default,
            events,
            callback,
        )
        .map_err(|_| {
            InputError::Capture(
                "CGEventTap creation failed (is the process trusted for Accessibility?)".into(),
            )
        })
    }

    fn pin_cursor(st: &mut TapState, ev: &CGEvent) {
        if st.anchor.is_none() {
            st.anchor = Some(ev.location());
            if !st.cursor_hidden && CGDisplay::hide_cursor(&CGDisplay::main()).is_ok() {
                st.cursor_hidden = true;
            }
        }
        if let Some(anchor) = st.anchor {
            if let Err(e) = CGDisplay::warp_mouse_cursor_position(anchor) {
                log::warn!("cursor warp failed: {e}");
            }
        }
    }

    fn translate(event_type: CGEventType, ev: &CGEvent, st: &mut TapState, out: &mut EventBuf) {
        match event_type {
            CGEventType::KeyDown | CGEventType::KeyUp => {
                let vk = ev.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE) as u16;
                match keymap::mac_to_evdev(vk) {
                    Some(key) => {
                        let down = matches!(event_type, CGEventType::KeyDown);
                        out.push(if down {
                            InputEvent::KeyboardKeyDown { key, time: 0 }
                        } else {
                            InputEvent::KeyboardKeyUp { key, time: 0 }
                        });
                    }
                    None => log::debug!("dropping unmapped macOS key code {vk:#x}"),
                }
            }
            CGEventType::FlagsChanged => {
                let flags = ev.get_flags();
                let mut depressed = Modifiers::empty();
                if flags.contains(CGEventFlags::CGEventFlagShift) {
                    depressed |= Modifiers::SHIFT;
                }
                if flags.contains(CGEventFlags::CGEventFlagControl) {
                    depressed |= Modifiers::CONTROL;
                }
                if flags.contains(CGEventFlags::CGEventFlagAlternate) {
                    depressed |= Modifiers::MOD1;
                }
                if flags.contains(CGEventFlags::CGEventFlagCommand) {
                    depressed |= Modifiers::MOD4;
                }
                if flags.contains(CGEventFlags::CGEventFlagAlphaShift) {
                    depressed |= Modifiers::LOCK;
                }

                let vk = ev.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE) as u16;
                if let Some(key) = keymap::mac_to_evdev(vk) {
                    // Press/release comes from *this key's own* flag bit. Upstream compares the
                    // whole mask against the previous one (`depressed > previous`), which
                    // mis-detects the release of Shift while Control is still held.
                    let mask = keymap::held_mask(key) | keymap::lock_mask(key);
                    let down = !mask.is_empty() && depressed.intersects(mask);
                    out.push(if down {
                        InputEvent::KeyboardKeyDown { key, time: 0 }
                    } else {
                        InputEvent::KeyboardKeyUp { key, time: 0 }
                    });
                }
                st.mods = depressed;
                out.push(modifier_state(st.mods));
            }
            CGEventType::MouseMoved
            | CGEventType::LeftMouseDragged
            | CGEventType::RightMouseDragged
            | CGEventType::OtherMouseDragged => {
                let dx = ev.get_double_value_field(EventField::MOUSE_EVENT_DELTA_X);
                let dy = ev.get_double_value_field(EventField::MOUSE_EVENT_DELTA_Y);
                if dx != 0.0 || dy != 0.0 {
                    out.push(InputEvent::MouseMove { dx, dy, time: 0 });
                }
            }
            CGEventType::LeftMouseDown => out.push(InputEvent::MouseButtonDown {
                button: super::proto::BTN_LEFT,
                time: 0,
            }),
            CGEventType::LeftMouseUp => out.push(InputEvent::MouseButtonUp {
                button: super::proto::BTN_LEFT,
                time: 0,
            }),
            CGEventType::RightMouseDown => out.push(InputEvent::MouseButtonDown {
                button: super::proto::BTN_RIGHT,
                time: 0,
            }),
            CGEventType::RightMouseUp => out.push(InputEvent::MouseButtonUp {
                button: super::proto::BTN_RIGHT,
                time: 0,
            }),
            CGEventType::OtherMouseDown | CGEventType::OtherMouseUp => {
                let down = matches!(event_type, CGEventType::OtherMouseDown);
                let number = ev.get_integer_value_field(EventField::MOUSE_EVENT_BUTTON_NUMBER);
                // macOS reports back/forward as button 3/4; everything else is the middle button
                // (upstream's mapping).
                let button = match number {
                    3 => super::proto::BTN_BACK,
                    4 => super::proto::BTN_FORWARD,
                    _ => super::proto::BTN_MIDDLE,
                };
                out.push(if down {
                    InputEvent::MouseButtonDown { button, time: 0 }
                } else {
                    InputEvent::MouseButtonUp { button, time: 0 }
                });
            }
            CGEventType::ScrollWheel => {
                // When "Natural Scrolling" is off, macOS deltas use the opposite sign convention
                // from evdev; when it is on the system has already negated them.
                let natural = ev.get_integer_value_field(DIRECTION_INVERTED_FROM_DEVICE) != 0;
                let sign: i64 = if natural { 1 } else { -1 };

                if ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_IS_CONTINUOUS) != 0 {
                    // Touchpad / Magic Mouse: pixel deltas, keep them as pixels.
                    let v = -sign
                        * ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_POINT_DELTA_AXIS_1);
                    let h = -sign
                        * ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_POINT_DELTA_AXIS_2);
                    if v != 0 {
                        out.push(InputEvent::MouseScroll {
                            axis: super::proto::AXIS_VERTICAL,
                            pixels: v as f64,
                            time: 0,
                        });
                    }
                    if h != 0 {
                        out.push(InputEvent::MouseScroll {
                            axis: super::proto::AXIS_HORIZONTAL,
                            pixels: h as f64,
                            time: 0,
                        });
                    }
                } else {
                    let v =
                        sign * ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_DELTA_AXIS_1);
                    let h =
                        sign * ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_DELTA_AXIS_2);
                    if v != 0 {
                        out.push(InputEvent::MouseWheel {
                            axis: super::proto::AXIS_VERTICAL,
                            delta120: V120_STEPS_PER_LINE * v as i32,
                        });
                    }
                    if h != 0 {
                        out.push(InputEvent::MouseWheel {
                            axis: super::proto::AXIS_HORIZONTAL,
                            delta120: V120_STEPS_PER_LINE * h as i32,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    fn modifier_state(mods: Modifiers) -> InputEvent {
        InputEvent::ModifierState {
            depressed: mods.bits(),
            latched: 0,
            locked: (mods & Modifiers::LOCK).bits(),
            group: 0,
        }
    }

    /// Upstream's `configure_cf_settings`: shorten the local-event suppression interval so the
    /// cursor warp does not swallow the following motion event, and enable the private
    /// `SetsCursorInBackground` property (used by Barrier and friends) so the cursor can be hidden
    /// while the process is not focused.
    unsafe fn configure_cf_settings() {
        match CGEventSource::new(CGEventSourceStateID::CombinedSessionState) {
            Ok(source) => CGEventSourceSetLocalEventsSuppressionInterval(source, 0.05),
            Err(()) => log::warn!("could not create event source for suppression interval"),
        }

        let key = CString::new("SetsCursorInBackground").unwrap();
        let cf_key = CFStringCreateWithCString(
            kCFAllocatorDefault,
            key.as_ptr() as *const c_char,
            kCFStringEncodingUTF8,
        );
        if cf_key.is_null() {
            return;
        }
        if CGSSetConnectionProperty(
            _CGSDefaultConnection(),
            _CGSDefaultConnection(),
            cf_key,
            core_foundation::number::kCFBooleanTrue,
        ) != kCGErrorSuccess
        {
            // Private API: failure only means the cursor cannot be hidden in the background.
            log::warn!("SetsCursorInBackground not accepted; cursor may stay visible");
        }
        CFRelease(cf_key as *const std::ffi::c_void);
    }
}

// ---------------------------------------------------------------------------------------------
// macOS input injection: CGEventPost
//
// Ported from input-emulation/src/macos.rs. Kept: posting at the HID tap location, `FlagsChanged`
// events that carry the real key code and the `NX_DEVICE_*` bits, click-state tracking,
// drag-event selection for held buttons, screen-space clamping, natural-scroll replication and
// key repeat. Changed: the key-repeat task is folded into the injection thread (no second task,
// no `Notify`, ordering is trivially preserved).
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub mod mac_emulate {
    use super::keymap;
    use super::proto::InputEvent;
    use super::*;

    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use core_foundation_sys::preferences::{
        CFPreferencesGetAppBooleanValue, kCFPreferencesAnyApplication,
    };
    use core_graphics::base::CGFloat;
    use core_graphics::display::{
        CGDirectDisplayID, CGDisplayBounds, CGGetDisplaysWithRect, CGPoint, CGRect, CGSize,
    };
    use core_graphics::event::{
        CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGKeyCode, CGMouseButton,
        EventField, ScrollEventUnit,
    };
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
    use std::collections::HashSet;
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
    use std::thread::JoinHandle;

    const REPEAT_DELAY: Duration = Duration::from_millis(500);
    const REPEAT_INTERVAL: Duration = Duration::from_millis(32);
    const DOUBLE_CLICK_INTERVAL: Duration = Duration::from_millis(500);
    const LINES_PER_STEP: i32 = 3;

    // Device-dependent modifier bits from IOKit/hidsystem/IOLLEvent.h. Real hardware sets them;
    // macOS does not synthesise them for posted events, and Apple's Virtualization.framework guest
    // views read exactly these bits (upstream issue #450).
    const NX_DEVICE_L_CTRL: u64 = 0x0000_0001;
    const NX_DEVICE_L_SHIFT: u64 = 0x0000_0002;
    const NX_DEVICE_L_CMD: u64 = 0x0000_0008;
    const NX_DEVICE_L_ALT: u64 = 0x0000_0020;
    const NX_DEVICE_R_ALT: u64 = 0x0000_0040;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrusted() -> bool;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGPreflightPostEventAccess() -> bool;
    }

    /// One injection thread, driven by [`EmuCommand`]s.
    pub struct MacEmulator {
        tx: Sender<EmuCommand>,
        thread: Option<JoinHandle<()>>,
    }

    impl MacEmulator {
        pub fn spawn() -> Result<Self> {
            let accessibility = unsafe { AXIsProcessTrusted() };
            let post_events = unsafe { CGPreflightPostEventAccess() };
            if !accessibility {
                return Err(InputError::EmulationPermission(
                    "Accessibility access is required to post synthetic events (System Settings → \
                     Privacy & Security → Accessibility)."
                        .into(),
                ));
            }
            if !post_events {
                return Err(InputError::EmulationPermission(
                    "Input Control / Accessibility permission to post events is missing."
                        .into(),
                ));
            }

            let (tx, rx) = std::sync::mpsc::channel::<EmuCommand>();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
            let thread = std::thread::Builder::new()
                .name("remote-input-inject".into())
                .spawn(move || injection_thread(rx, ready_tx))?;
            ready_rx
                .recv()
                .map_err(|_| InputError::Emulation("injection thread died during setup".into()))??;
            Ok(Self { tx, thread: Some(thread) })
        }

        pub fn send(&self, cmd: EmuCommand) {
            if self.tx.send(cmd).is_err() {
                log::warn!("injection thread is gone, dropping command");
            }
        }

        pub fn shutdown(mut self) {
            let _ = self.tx.send(EmuCommand::Shutdown);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    struct RepeatState {
        vk: Option<CGKeyCode>,
        next: Option<Instant>,
    }

    impl RepeatState {
        fn idle() -> Self {
            Self { vk: None, next: None }
        }

        fn stop(&mut self) {
            self.vk = None;
            self.next = None;
        }
    }

    struct EmuState {
        source: CGEventSource,
        pressed_keys: HashSet<u32>,
        pressed_buttons: HashSet<u32>,
        previous_button: Option<u32>,
        previous_click: Option<Instant>,
        click_state: i64,
        mods: Modifiers,
        repeat: RepeatState,
        natural_scroll_key: CFString,
    }

    impl EmuState {
        fn new(source: CGEventSource) -> Self {
            Self {
                source,
                pressed_keys: HashSet::new(),
                pressed_buttons: HashSet::new(),
                previous_button: None,
                previous_click: None,
                click_state: 0,
                mods: Modifiers::empty(),
                repeat: RepeatState::idle(),
                natural_scroll_key: CFString::new("com.apple.swipescrolldirection"),
            }
        }

        fn natural_scroll(&self) -> bool {
            let mut valid: u8 = 0;
            let value = unsafe {
                CFPreferencesGetAppBooleanValue(
                    self.natural_scroll_key.as_concrete_TypeRef(),
                    kCFPreferencesAnyApplication,
                    &mut valid,
                )
            };
            // macOS factory default is on when the key is unset.
            valid == 0 || value != 0
        }

        fn mouse_location(&self) -> Option<CGPoint> {
            CGEvent::new(self.source.clone()).ok().map(|e| e.location())
        }

        fn post_key(&self, vk: CGKeyCode, down: bool) {
            let event = match CGEvent::new_keyboard_event(self.source.clone(), vk, down) {
                Ok(e) => e,
                Err(()) => {
                    log::warn!("could not create keyboard event for key {vk}");
                    return;
                }
            };
            let mut flags = to_cg_flags(self.mods);
            if keymap::is_mac_arrow_key(vk) {
                // Hardware arrow keys carry these; hotkey matchers rely on them.
                flags |= CGEventFlags::CGEventFlagNumericPad | CGEventFlags::CGEventFlagSecondaryFn;
            }
            event.set_flags(flags);
            event.post(CGEventTapLocation::HID);
        }

        fn post_modifier(&self, vk: CGKeyCode) {
            // A modifier change must be a `FlagsChanged` event that carries the real key code: a
            // bare `CGEvent::new()` defaults to key code 0 (`kVK_ANSI_A`) and every modifier change
            // would arrive as a phantom "A" (upstream issue #450).
            let Ok(event) = CGEvent::new_keyboard_event(self.source.clone(), vk, true) else {
                log::warn!("could not create modifier event for key {vk}");
                return;
            };
            event.set_type(CGEventType::FlagsChanged);
            event.set_flags(flags_changed_flags(self.mods));
            event.post(CGEventTapLocation::HID);
        }

        fn start_repeat(&mut self, vk: CGKeyCode) {
            self.post_key(vk, true);
            self.repeat.vk = Some(vk);
            self.repeat.next = Some(Instant::now() + REPEAT_DELAY);
        }

        fn tick(&mut self) {
            let Some(next) = self.repeat.next else { return };
            if Instant::now() < next {
                return;
            }
            if let Some(vk) = self.repeat.vk {
                self.post_key(vk, true);
            }
            self.repeat.next = Some(Instant::now() + REPEAT_INTERVAL);
        }

        fn timeout(&self) -> Duration {
            match self.repeat.next {
                Some(next) => next.saturating_duration_since(Instant::now()),
                None => Duration::from_secs(3600),
            }
        }

        fn consume(&mut self, event: InputEvent) {
            match event {
                InputEvent::KeyboardKeyDown { key, .. } => self.key(key, true),
                InputEvent::KeyboardKeyUp { key, .. } => self.key(key, false),
                InputEvent::MouseButtonDown { button, .. } => self.button(button, true),
                InputEvent::MouseButtonUp { button, .. } => self.button(button, false),
                InputEvent::MouseMove { dx, dy, .. } => self.motion(dx, dy),
                InputEvent::MouseWheel { axis, delta120 } => self.wheel(axis, delta120),
                InputEvent::MouseScroll { axis, pixels, .. } => self.scroll(axis, pixels),
                InputEvent::ModifierState { depressed, locked, .. } => {
                    // The per-key handler above already posts a `FlagsChanged` for every modifier
                    // key transition; here only the tracked mask is updated (posting again would
                    // duplicate the event).
                    self.mods = Modifiers::from_bits_truncate(depressed)
                        | Modifiers::from_bits_truncate(locked & Modifiers::LOCK.bits());
                }
                InputEvent::DeviceDisconnect { .. } => self.release_all(),
                InputEvent::StateSync { .. } => { /* reconciled by the engine before injection */ }
            }
        }

        fn key(&mut self, key: u32, down: bool) {
            let Some(vk) = keymap::evdev_to_mac(key) else {
                log::debug!("no macOS key code for evdev {key}, dropping");
                return;
            };

            if keymap::is_modifier(key) {
                // Lock keys toggle on press (macOS semantics); held modifiers follow the event.
                if !keymap::lock_mask(key).is_empty() {
                    if down {
                        self.mods.toggle(keymap::lock_mask(key));
                    }
                } else if down {
                    self.mods |= keymap::held_mask(key);
                } else {
                    self.mods.remove(keymap::held_mask(key));
                }
                if down {
                    self.pressed_keys.insert(key);
                } else {
                    self.pressed_keys.remove(&key);
                }
                // Modifiers must not enter the repeat machinery: there is a single repeat slot and
                // a second modifier press would cancel the first one's repeat and post a key-up
                // while it is still held (upstream issues #450/#357).
                self.post_modifier(vk);
                return;
            }

            if down {
                if self.pressed_keys.insert(key) {
                    self.start_repeat(vk);
                }
            } else {
                self.pressed_keys.remove(&key);
                if self.repeat.vk == Some(vk) {
                    self.repeat.stop();
                }
                self.post_key(vk, false);
            }
        }

        fn button(&mut self, button: u32, down: bool) {
            let cg_button_number: Option<i64> = match button {
                super::proto::BTN_BACK => Some(3),
                super::proto::BTN_FORWARD => Some(4),
                _ => None,
            };
            let (event_type, mouse_button) = match (button, down) {
                (b, true) if b == super::proto::BTN_LEFT => {
                    (CGEventType::LeftMouseDown, CGMouseButton::Left)
                }
                (b, false) if b == super::proto::BTN_LEFT => {
                    (CGEventType::LeftMouseUp, CGMouseButton::Left)
                }
                (b, true) if b == super::proto::BTN_RIGHT => {
                    (CGEventType::RightMouseDown, CGMouseButton::Right)
                }
                (b, false) if b == super::proto::BTN_RIGHT => {
                    (CGEventType::RightMouseUp, CGMouseButton::Right)
                }
                (_, true) => (CGEventType::OtherMouseDown, CGMouseButton::Center),
                (_, false) => (CGEventType::OtherMouseUp, CGMouseButton::Center),
            };

            if down {
                self.pressed_buttons.insert(button);
                // Double-click tracking uses the evdev button code so back/forward do not alias
                // with the middle button.
                if self.previous_button == Some(button)
                    && self
                        .previous_click
                        .is_some_and(|i| i.elapsed() < DOUBLE_CLICK_INTERVAL)
                {
                    self.click_state += 1;
                } else {
                    self.click_state = 1;
                }
                self.previous_button = Some(button);
                self.previous_click = Some(Instant::now());
            } else {
                self.pressed_buttons.remove(&button);
            }

            let Some(location) = self.mouse_location() else {
                log::warn!("could not read cursor location for button event");
                return;
            };
            let Ok(event) =
                CGEvent::new_mouse_event(self.source.clone(), event_type, location, mouse_button)
            else {
                log::warn!("could not create mouse button event");
                return;
            };
            event.set_integer_value_field(
                EventField::MOUSE_EVENT_CLICK_STATE,
                self.click_state.max(1),
            );
            if let Some(number) = cg_button_number {
                event.set_integer_value_field(EventField::MOUSE_EVENT_BUTTON_NUMBER, number);
            }
            event.post(CGEventTapLocation::HID);
        }

        fn motion(&mut self, dx: f64, dy: f64) {
            let Some(mut location) = self.mouse_location() else {
                log::warn!("could not read cursor location for motion");
                return;
            };
            let (nx, ny) = clamp_to_screen_space(location.x, location.y, dx, dy);
            location.x = nx;
            location.y = ny;

            // While a button is held the event must be a drag event, otherwise macOS drops the
            // movement for drag-sensitive consumers.
            let event_type = self
                .pressed_buttons
                .iter()
                .next()
                .map(|&b| match b {
                    x if x == super::proto::BTN_LEFT => CGEventType::LeftMouseDragged,
                    x if x == super::proto::BTN_RIGHT => CGEventType::RightMouseDragged,
                    _ => CGEventType::OtherMouseDragged,
                })
                .unwrap_or(CGEventType::MouseMoved);

            let Ok(event) = CGEvent::new_mouse_event(
                self.source.clone(),
                event_type,
                location,
                CGMouseButton::Left,
            ) else {
                log::warn!("could not create mouse move event");
                return;
            };
            event.set_integer_value_field(EventField::MOUSE_EVENT_DELTA_X, dx as i64);
            event.set_integer_value_field(EventField::MOUSE_EVENT_DELTA_Y, dy as i64);
            event.post(CGEventTapLocation::HID);

            // Any non-button event resets the click sequence, so two clicks separated by mouse
            // movement are not a double click.
            self.click_state = 0;
        }

        fn wheel(&mut self, axis: u8, delta120: i32) {
            // Synthetic events bypass the natural-scrolling preference, so it is replicated here
            // (upstream issue #481).
            let value = if self.natural_scroll() { delta120 } else { -delta120 };
            let lines = value / (120 / LINES_PER_STEP);
            if lines == 0 {
                return;
            }
            self.post_scroll(ScrollEventUnit::LINE, axis, lines);
        }

        fn scroll(&mut self, axis: u8, pixels: f64) {
            let value = if self.natural_scroll() { -pixels as i32 } else { pixels as i32 };
            if value == 0 {
                return;
            }
            self.post_scroll(ScrollEventUnit::PIXEL, axis, value);
        }

        fn post_scroll(&mut self, unit: u32, axis: u8, value: i32) {
            let (count, w1, w2, w3) = match axis {
                super::proto::AXIS_VERTICAL => (1u32, value, 0, 0),
                super::proto::AXIS_HORIZONTAL => (2u32, 0, value, 0),
                other => {
                    log::warn!("invalid scroll axis {other}");
                    return;
                }
            };
            let Ok(event) =
                CGEvent::new_scroll_event(self.source.clone(), unit, count, w1, w2, w3)
            else {
                log::warn!("could not create scroll event");
                return;
            };
            event.post(CGEventTapLocation::HID);
            self.click_state = 0;
        }

        /// Release everything that is currently held. Called on disconnect, on timeout and on
        /// `release_all_inputs()`; a stuck modifier must never survive it.
        fn release_all(&mut self) {
            let keys: Vec<u32> = self.pressed_keys.drain().collect();
            let buttons: Vec<u32> = self.pressed_buttons.drain().collect();
            self.repeat.stop();

            for key in keys {
                let Some(vk) = keymap::evdev_to_mac(key) else { continue };
                if keymap::is_modifier(key) {
                    if !keymap::lock_mask(key).is_empty() {
                        // Turning a lock off is a press, not a release.
                        self.mods.remove(keymap::lock_mask(key));
                    } else {
                        self.mods.remove(keymap::held_mask(key));
                    }
                    self.post_modifier(vk);
                } else {
                    self.post_key(vk, false);
                }
                log::debug!("released stuck key {key}");
            }
            for button in buttons {
                self.button(button, false);
            }
            // Clear whatever modifier state is left over.
            self.mods = Modifiers::empty();
            self.click_state = 0;
            self.previous_button = None;
        }
    }

    fn injection_thread(rx: Receiver<EmuCommand>, ready: Sender<Result<()>>) {
        let source = match CGEventSource::new(CGEventSourceStateID::CombinedSessionState) {
            Ok(s) => s,
            Err(()) => {
                let _ = ready.send(Err(InputError::Emulation(
                    "could not create a CGEventSource".into(),
                )));
                return;
            }
        };
        let _ = ready.send(Ok(()));

        let mut state = EmuState::new(source);
        loop {
            match rx.recv_timeout(state.timeout()) {
                Ok(EmuCommand::Event(event)) => state.consume(event),
                Ok(EmuCommand::ReleaseAll) => state.release_all(),
                Ok(EmuCommand::Shutdown) => break,
                Err(RecvTimeoutError::Timeout) => state.tick(),
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        state.release_all();
        log::debug!("injection thread exiting");
    }

    fn to_cg_flags(mods: Modifiers) -> CGEventFlags {
        let mut flags = CGEventFlags::empty();
        if mods.contains(Modifiers::SHIFT) {
            flags |= CGEventFlags::CGEventFlagShift;
        }
        if mods.contains(Modifiers::LOCK) {
            flags |= CGEventFlags::CGEventFlagAlphaShift;
        }
        if mods.contains(Modifiers::CONTROL) {
            flags |= CGEventFlags::CGEventFlagControl;
        }
        if mods.contains(Modifiers::MOD1) || mods.contains(Modifiers::MOD5) {
            flags |= CGEventFlags::CGEventFlagAlternate;
        }
        if mods.contains(Modifiers::MOD4) {
            flags |= CGEventFlags::CGEventFlagCommand;
        }
        flags
    }

    fn flags_changed_flags(mods: Modifiers) -> CGEventFlags {
        let mut device_bits: u64 = 0;
        if mods.contains(Modifiers::SHIFT) {
            device_bits |= NX_DEVICE_L_SHIFT;
        }
        if mods.contains(Modifiers::CONTROL) {
            device_bits |= NX_DEVICE_L_CTRL;
        }
        if mods.contains(Modifiers::MOD1) {
            device_bits |= NX_DEVICE_L_ALT;
        }
        if mods.contains(Modifiers::MOD5) {
            device_bits |= NX_DEVICE_R_ALT;
        }
        if mods.contains(Modifiers::MOD4) {
            device_bits |= NX_DEVICE_L_CMD;
        }
        let flags = to_cg_flags(mods) | CGEventFlags::CGEventFlagNonCoalesced;
        CGEventFlags::from_bits_retain(flags.bits() | device_bits)
    }

    fn display_at_point(x: CGFloat, y: CGFloat) -> Option<CGDirectDisplayID> {
        let mut displays = [0 as CGDirectDisplayID; 16];
        let mut count: u32 = 0;
        let rect = CGRect::new(&CGPoint::new(x, y), &CGSize::new(0.0, 0.0));
        let err = unsafe {
            CGGetDisplaysWithRect(rect, 16, displays.as_mut_ptr(), &mut count as *mut u32)
        };
        if err != 0 || count == 0 {
            return None;
        }
        displays.first().copied()
    }

    fn display_bounds(display: CGDirectDisplayID) -> (CGFloat, CGFloat, CGFloat, CGFloat) {
        unsafe {
            let bounds = CGDisplayBounds(display);
            (
                bounds.origin.x,
                bounds.origin.y,
                bounds.origin.x + bounds.size.width,
                bounds.origin.y + bounds.size.height,
            )
        }
    }

    fn clamp_to_screen_space(
        x: CGFloat,
        y: CGFloat,
        dx: CGFloat,
        dy: CGFloat,
    ) -> (CGFloat, CGFloat) {
        let Some(current) = display_at_point(x, y) else {
            log::warn!("could not determine the display under the cursor");
            return (x, y);
        };
        let next_x = x + dx;
        let next_y = y + dy;
        let target = display_at_point(next_x, next_y).unwrap_or(current);
        let (min_x, min_y, max_x, max_y) = display_bounds(target);
        (next_x.clamp(min_x, max_x - 1.0), next_y.clamp(min_y, max_y - 1.0))
    }
}

// ---------------------------------------------------------------------------------------------
// Engine: one async task that owns capture, every connection, the injection thread and all input
// state. Nothing here polls: sockets are read by their own tasks that push into one channel, the
// capture backends push into another, and the engine only wakes up for an actual event or a timer.
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[path = "../../example/remote_input.rs"]
mod linux_core;

#[cfg(target_os = "linux")]
pub use linux_core::engine;

#[cfg(target_os = "macos")]
pub mod engine {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Capture → engine channel capacity. Bounded on purpose: input that cannot be delivered must
    /// either block the capture thread (key events) or be dropped (pointer motion), never grow
    /// without limit.
    pub const CAP_CHANNEL: usize = 512;

    /// Timer resolution of the engine loop. Pings, timeouts and state syncs are derived from it.
    const TICK: Duration = Duration::from_millis(100);

    // -----------------------------------------------------------------------------------------
    // Configuration and status
    // -----------------------------------------------------------------------------------------

    #[derive(Clone, Debug)]
    pub struct Config {
        /// UDP port for [`super::RemoteInput::start_listener`]. 0 picks a free port.
        pub listen_port: u16,
        /// Name of the virtual device (Linux) / log tag. Prefixed so the capture side can skip
        /// this process's own devices and never create a feedback loop.
        pub device_name: String,
        /// Only capture devices whose `/dev/input/by-id` name starts with this string. Empty = all.
        pub device_prefix: String,
        /// Accept *any* client certificate on the listening side. Off by default: an unauthenticated
        /// remote keyboard is a remote code execution primitive.
        pub allow_any_peer: bool,
        /// Pin the peer certificate on the dialling side (SHA-256 of the DER certificate).
        pub expected_peer_fingerprint: Option<transport::Fingerprint>,
        pub connect_timeout: Duration,
        pub ping_interval: Duration,
        /// A peer that sent nothing for this long is considered dead and is released.
        pub idle_timeout: Duration,
        /// How often the authoritative input state is re-sent while forwarding.
        pub sync_interval: Duration,
        /// Whether `Enter` from a peer may cause local injection at all.
        pub accept_remote_input: bool,
        /// Local panic chord: when all of these evdev keys are held, forwarding stops and every
        /// key is released. Empty disables the chord.
        pub release_bind: Vec<u32>,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                listen_port: 4242,
                device_name: "remote-input".to_string(),
                device_prefix: String::new(),
                allow_any_peer: false,
                expected_peer_fingerprint: None,
                connect_timeout: Duration::from_secs(5),
                ping_interval: Duration::from_millis(500),
                idle_timeout: Duration::from_secs(1),
                sync_interval: Duration::from_millis(200),
                accept_remote_input: true,
                release_bind: Vec::new(),
            }
        }
    }

    impl Config {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_listen_port(mut self, port: u16) -> Self {
            self.listen_port = port;
            self
        }

        pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
            self.device_name = name.into();
            self
        }

        /// Pin the dialled peer by fingerprint (hex, colons optional).
        pub fn with_pinned_peer(mut self, hex: &str) -> Result<Self> {
            let fp = transport::parse_fingerprint_hex(hex)
                .ok_or_else(|| InputError::Network(format!("invalid fingerprint: {hex}")))?;
            self.expected_peer_fingerprint = Some(fp);
            Ok(self)
        }

        /// Install the default panic chord: Ctrl+Alt+Esc.
        pub fn with_default_release_bind(mut self) -> Self {
            self.release_bind = vec![
                keymap::KEY_LEFTCTRL,
                keymap::KEY_LEFTALT,
                keymap::KEY_ESC,
            ];
            self
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PeerStatus {
        pub addr: SocketAddr,
        pub handshake_done: bool,
        /// Local input is being forwarded to this peer (Enter/Ack completed).
        pub forwarding_to_peer: bool,
        /// This peer's input is being injected locally.
        pub injecting_from_peer: bool,
        pub last_rx_ms_ago: u64,
        pub rtt_ms: Option<u32>,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ConnectionStatus {
        pub capture_active: bool,
        pub forwarding: bool,
        pub listening_port: Option<u16>,
        pub peers: Vec<PeerStatus>,
        pub local_fingerprint: String,
        pub emulation_ready: bool,
        pub last_error: Option<String>,
    }

    impl ConnectionStatus {
        pub fn is_connected(&self) -> bool {
            !self.peers.is_empty()
        }

        pub fn injecting(&self) -> bool {
            self.peers.iter().any(|p| p.injecting_from_peer)
        }
    }

    // -----------------------------------------------------------------------------------------
    // Internal plumbing
    // -----------------------------------------------------------------------------------------

    type Reply<T> = oneshot::Sender<Result<T>>;

    enum Command {
        StartCapture(Reply<()>),
        StopCapture(Reply<()>),
        Connect { host: String, port: u16, reply: Reply<()> },
        Disconnect(Reply<()>),
        SetForwarding { on: bool, reply: Reply<()> },
        ReleaseAll(Reply<()>),
        StartListener(Reply<u16>),
        StopListener(Reply<()>),
        Authorize { fingerprint: String, allow: bool, reply: Reply<()> },
        Shutdown(Reply<()>),
    }

    enum NetMsg {
        Event(SocketAddr, ProtoEvent),
        Closed(SocketAddr),
    }

    struct Incoming {
        conn: transport::ArcConn,
        addr: SocketAddr,
    }

    struct Peer {
        conn: transport::ArcConn,
        /// True for connections this instance accepted: they die with the listener.
        inbound: bool,
        handshake: bool,
        forwarded: bool,
        injecting: bool,
        last_rx: Instant,
        last_ping: Option<Instant>,
        rtt_ms: Option<u32>,
    }

    /// Platform capture backend, type-erased so the engine stays platform independent.
    enum CaptureHandle {
        #[cfg(target_os = "macos")]
        Mac(mac_capture::MacCapture),
        #[cfg(target_os = "linux")]
        Linux(linux_capture::LinuxCapture),
    }

    impl CaptureHandle {
        fn set_forwarding(&self, on: bool) {
            match self {
                #[cfg(target_os = "macos")]
                CaptureHandle::Mac(c) => c.set_forwarding(on),
                #[cfg(target_os = "linux")]
                CaptureHandle::Linux(c) => c.set_forwarding(on),
            }
        }

        async fn stop(self) {
            match self {
                #[cfg(target_os = "macos")]
                CaptureHandle::Mac(c) => c.stop(),
                #[cfg(target_os = "linux")]
                CaptureHandle::Linux(c) => c.stop().await,
            }
        }
    }

    /// Platform injection backend.
    enum EmulatorHandle {
        #[cfg(target_os = "macos")]
        Mac(mac_emulate::MacEmulator),
        #[cfg(target_os = "linux")]
        Linux(linux_emulate::UinputEmulator),
    }

    impl EmulatorHandle {
        fn spawn(device_name: &str) -> Result<Self> {
            #[cfg(target_os = "macos")]
            {
                let _ = device_name;
                Ok(EmulatorHandle::Mac(mac_emulate::MacEmulator::spawn()?))
            }
            #[cfg(target_os = "linux")]
            {
                Ok(EmulatorHandle::Linux(linux_emulate::UinputEmulator::spawn(
                    device_name,
                )?))
            }
        }

        fn send(&self, cmd: EmuCommand) {
            match self {
                #[cfg(target_os = "macos")]
                EmulatorHandle::Mac(e) => e.send(cmd),
                #[cfg(target_os = "linux")]
                EmulatorHandle::Linux(e) => e.send(cmd),
            }
        }

        fn shutdown(self) {
            match self {
                #[cfg(target_os = "macos")]
                EmulatorHandle::Mac(e) => e.shutdown(),
                #[cfg(target_os = "linux")]
                EmulatorHandle::Linux(e) => e.shutdown(),
            }
        }
    }

    struct ListenerHandle {
        task: tokio::task::JoinHandle<()>,
        port: u16,
    }

    struct Engine {
        cfg: Config,
        identity: transport::Identity,
        authorized: Arc<RwLock<HashSet<transport::Fingerprint>>>,
        status: Arc<StdMutex<ConnectionStatus>>,

        cap_tx: mpsc::Sender<InputEvent>,
        net_tx: mpsc::Sender<NetMsg>,
        inc_tx: mpsc::Sender<Incoming>,

        capture: Option<CaptureHandle>,
        emulator: Option<EmulatorHandle>,
        listener: Option<ListenerHandle>,
        forwarding_flag: Arc<AtomicBool>,
        forwarding: bool,

        peers: HashMap<SocketAddr, Peer>,
        /// The connection this instance dialled, for `disconnect_remote()`.
        dialed: Option<SocketAddr>,

        // Sender-side (host) state: what this machine has pressed and must release.
        local_keys: HashSet<u32>,
        local_buttons: HashSet<u32>,
        mods: keymap::ModifierTracker,
        sync_seq: u32,

        // Host-only Super × 3 control hotkey.
        hotkey_held: bool,
        hotkey_releases: u32,
        hotkey_last_release: Option<Instant>,

        // Receiver-side (client) state: what has been injected and must be released.
        remote_keys: HashSet<u32>,
        remote_buttons: HashSet<u32>,
        last_sync_seq: u32,

        last_error: Option<String>,
        tick_count: u64,
        last_ping: Instant,
        last_sync: Instant,
    }

    impl Engine {
        fn new(
            cfg: Config,
            identity: transport::Identity,
            status: Arc<StdMutex<ConnectionStatus>>,
            cap_tx: mpsc::Sender<InputEvent>,
            net_tx: mpsc::Sender<NetMsg>,
            inc_tx: mpsc::Sender<Incoming>,
        ) -> Self {
            let now = Instant::now();
            Self {
                cfg,
                identity,
                authorized: Arc::new(RwLock::new(HashSet::new())),
                status,
                cap_tx,
                net_tx,
                inc_tx,
                capture: None,
                emulator: None,
                listener: None,
                forwarding_flag: Arc::new(AtomicBool::new(false)),
                forwarding: false,
                peers: HashMap::new(),
                dialed: None,
                local_keys: HashSet::new(),
                local_buttons: HashSet::new(),
                mods: keymap::ModifierTracker::new(),
                sync_seq: 0,
                hotkey_held: false,
                hotkey_releases: 0,
                hotkey_last_release: None,
                remote_keys: HashSet::new(),
                remote_buttons: HashSet::new(),
                last_sync_seq: 0,
                last_error: None,
                tick_count: 0,
                last_ping: now,
                last_sync: now,
            }
        }

        async fn run(
            mut self,
            mut cmd_rx: mpsc::Receiver<Command>,
            mut cap_rx: mpsc::Receiver<InputEvent>,
            mut net_rx: mpsc::Receiver<NetMsg>,
            mut inc_rx: mpsc::Receiver<Incoming>,
        ) {
            let mut ticker = tokio::time::interval(TICK);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    cmd = cmd_rx.recv() => match cmd {
                        Some(cmd) => {
                            if !self.on_command(cmd).await {
                                break;
                            }
                        }
                        None => break,
                    },
                    Some(event) = cap_rx.recv() => self.on_local_event(event).await,
                    Some(msg) = net_rx.recv() => self.on_net(msg).await,
                    Some(incoming) = inc_rx.recv() => self.on_incoming(incoming).await,
                    _ = ticker.tick() => self.on_tick().await,
                }
                self.publish();
            }
            self.shutdown_inner().await;
        }

        // -- helpers --------------------------------------------------------------------------

        async fn send_to(&self, conn: &transport::ArcConn, event: ProtoEvent) {
            let mut buf = [0u8; proto::MAX_FRAME_SIZE];
            let n = proto::encode(&event, &mut buf);
            if let Err(e) = conn.send(&buf[..n]).await {
                log::warn!("send failed: {e}");
            }
        }

        /// Send to every peer, or only to those that granted us control.
        async fn broadcast(&self, event: ProtoEvent, only_forwarded: bool) {
            let targets: Vec<transport::ArcConn> = self
                .peers
                .values()
                .filter(|p| !only_forwarded || p.forwarded)
                .map(|p| p.conn.clone())
                .collect();
            for conn in targets {
                self.send_to(&conn, event).await;
            }
        }

        fn spawn_reader(&self, addr: SocketAddr, conn: transport::ArcConn) {
            let tx = self.net_tx.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; proto::MAX_FRAME_SIZE];
                loop {
                    match conn.recv(&mut buf).await {
                        Ok(0) => continue,
                        Ok(n) => match proto::decode(&buf[..n]) {
                            Ok(event) => {
                                if tx.send(NetMsg::Event(addr, event)).await.is_err() {
                                    return;
                                }
                            }
                            Err(e) => log::warn!("{addr}: {e}"),
                        },
                        Err(e) => {
                            log::debug!("{addr}: connection closed: {e}");
                            let _ = tx.send(NetMsg::Closed(addr)).await;
                            return;
                        }
                    }
                }
            });
        }

        fn publish(&self) {
            let now = Instant::now();
            let mut peers: Vec<PeerStatus> = self
                .peers
                .iter()
                .map(|(addr, p)| PeerStatus {
                    addr: *addr,
                    handshake_done: p.handshake,
                    forwarding_to_peer: p.forwarded,
                    injecting_from_peer: p.injecting,
                    last_rx_ms_ago: now.duration_since(p.last_rx).as_millis() as u64,
                    rtt_ms: p.rtt_ms,
                })
                .collect();
            peers.sort_by_key(|p| p.addr.to_string());
            let snapshot = ConnectionStatus {
                capture_active: self.capture.is_some(),
                forwarding: self.forwarding,
                listening_port: self.listener.as_ref().map(|l| l.port),
                peers,
                local_fingerprint: transport::fingerprint_hex(&self.identity.fingerprint),
                emulation_ready: self.emulator.is_some(),
                last_error: self.last_error.clone(),
            };
            if let Ok(mut guard) = self.status.lock() {
                *guard = snapshot;
            }
        }

        // -- commands -------------------------------------------------------------------------

        /// Returns false when the engine should stop.
        async fn on_command(&mut self, cmd: Command) -> bool {
            match cmd {
                Command::StartCapture(reply) => {
                    let _ = reply.send(self.start_capture_inner().await);
                }
                Command::StopCapture(reply) => {
                    let _ = reply.send(self.stop_capture_inner().await);
                }
                Command::Connect { host, port, reply } => {
                    let _ = reply.send(self.connect_inner(&host, port).await);
                }
                Command::Disconnect(reply) => {
                    let _ = reply.send(self.disconnect_inner().await);
                }
                Command::SetForwarding { on, reply } => {
                    let res = if on {
                        self.enable_forwarding().await
                    } else {
                        self.disable_forwarding().await
                    };
                    let _ = reply.send(res);
                }
                Command::ReleaseAll(reply) => {
                    self.release_forwarded().await;
                    self.release_injected();
                    let _ = reply.send(Ok(()));
                }
                Command::StartListener(reply) => {
                    let _ = reply.send(self.start_listener_inner().await);
                }
                Command::StopListener(reply) => {
                    let _ = reply.send(self.stop_listener_inner().await);
                }
                Command::Authorize { fingerprint, allow, reply } => {
                    let res = self.authorize_inner(&fingerprint, allow);
                    let _ = reply.send(res);
                }
                Command::Shutdown(reply) => {
                    let _ = reply.send(Ok(()));
                    return false;
                }
            }
            true
        }

        async fn start_capture_inner(&mut self) -> Result<()> {
            if self.capture.is_some() {
                return Ok(());
            }
            let tx = self.cap_tx.clone();
            let flag = self.forwarding_flag.clone();

            #[cfg(target_os = "macos")]
            let capture = CaptureHandle::Mac(mac_capture::MacCapture::start(tx, flag)?);

            #[cfg(target_os = "linux")]
            let capture =
                CaptureHandle::Linux(linux_capture::LinuxCapture::start(
                    tx,
                    flag,
                    &self.cfg.device_prefix,
                )?);

            self.capture = Some(capture);
            log::info!("capture started");
            Ok(())
        }

        async fn stop_capture_inner(&mut self) -> Result<()> {
            let Some(capture) = self.capture.take() else {
                return Ok(());
            };
            self.forwarding = false;
            self.forwarding_flag.store(false, Ordering::SeqCst);
            capture.set_forwarding(false);
            capture.stop().await;

            // Tell peers to drop whatever they think is held, then release locally.
            self.broadcast(
                ProtoEvent::Input(InputEvent::DeviceDisconnect {
                    reason: DisconnectReason::CaptureStopped,
                }),
                false,
            )
            .await;
            self.release_forwarded().await;
            for peer in self.peers.values_mut() {
                peer.forwarded = false;
            }
            self.local_keys.clear();
            self.local_buttons.clear();
            self.mods.reset();
            log::info!("capture stopped");
            Ok(())
        }

        async fn connect_inner(&mut self, host: &str, port: u16) -> Result<()> {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| InputError::Network(format!("cannot resolve {host}:{port}: {e}")))?
                .collect();
            if addrs.is_empty() {
                return Err(InputError::Network(format!("{host}:{port} resolved to nothing")));
            }
            let (conn, addr) = transport::dial_any(
                &addrs,
                self.identity.cert.clone(),
                self.cfg.expected_peer_fingerprint,
                self.cfg.connect_timeout,
            )
            .await?;

            if let Some(old) = self.peers.remove(&addr) {
                let _ = old.conn.close().await;
            }
            self.peers.insert(
                addr,
                Peer {
                    conn: conn.clone(),
                    inbound: false,
                    handshake: false,
                    forwarded: false,
                    injecting: false,
                    last_rx: Instant::now(),
                    last_ping: None,
                    rtt_ms: None,
                },
            );
            self.dialed = Some(addr);
            self.spawn_reader(addr, conn.clone());
            self.send_to(&conn, ProtoEvent::Hello(proto::PROTOCOL_VERSION)).await;
            log::info!("connected to {addr}");
            self.last_error = None;
            Ok(())
        }

        async fn disconnect_inner(&mut self) -> Result<()> {
            let Some(addr) = self.dialed.take() else {
                return Ok(());
            };
            if let Some(peer) = self.peers.remove(&addr) {
                if peer.injecting {
                    self.release_injected();
                }
                let _ = self
                    .send_to(
                        &peer.conn,
                        ProtoEvent::Input(InputEvent::DeviceDisconnect {
                            reason: DisconnectReason::RemoteRequest,
                        }),
                    )
                    .await;
                let _ = peer.conn.close().await;
            }
            log::info!("disconnected from {addr}");
            Ok(())
        }

        fn reset_super_hotkey(&mut self) {
            self.hotkey_releases = 0;
            self.hotkey_last_release = None;
        }

        async fn toggle_control_from_hotkey(&mut self) {
            let result = if self.forwarding {
                self.disable_forwarding().await
            } else {
                self.enable_forwarding().await
            };
            if let Err(error) = result {
                self.last_error = Some(error.to_string());
                log::warn!("Super x 3 control toggle failed: {error}");
            } else {
                self.last_error = None;
            }
        }

        async fn enable_forwarding(&mut self) -> Result<()> {
            if self.forwarding {
                return Ok(());
            }
            if self.capture.is_none() {
                let msg = "start_capture() must succeed before enable_remote_input()";
                self.last_error = Some(msg.to_string());
                return Err(InputError::Capture(msg.into()));
            }
            self.forwarding = true;
            self.forwarding_flag.store(true, Ordering::SeqCst);
            if let Some(capture) = &self.capture {
                capture.set_forwarding(true);
            }
            // Enter/Ack is upstream's control-transfer handshake: only a peer that acknowledged
            // the Enter frame receives input.
            self.broadcast(ProtoEvent::Enter(Direction::Right), false).await;
            self.last_sync = Instant::now();
            self.sync_seq = 0;
            log::info!("remote input enabled");
            Ok(())
        }

        async fn disable_forwarding(&mut self) -> Result<()> {
            if !self.forwarding {
                return Ok(());
            }
            self.forwarding = false;
            self.forwarding_flag.store(false, Ordering::SeqCst);
            if let Some(capture) = &self.capture {
                capture.set_forwarding(false);
            }
            self.release_forwarded().await;
            self.broadcast(ProtoEvent::Leave(0), false).await;
            for peer in self.peers.values_mut() {
                peer.forwarded = false;
            }
            log::info!("remote input disabled");
            Ok(())
        }

        async fn start_listener_inner(&mut self) -> Result<u16> {
            if let Some(listener) = &self.listener {
                return Ok(listener.port);
            }
            let bound = transport::bind(
                self.cfg.listen_port,
                self.identity.cert.clone(),
                self.authorized.clone(),
                self.cfg.allow_any_peer,
            )
            .await?;
            let port = bound.port;
            let tx = self.inc_tx.clone();
            let task = tokio::spawn(accept_loop(bound.listener, tx));
            self.listener = Some(ListenerHandle { task, port });
            log::info!("listening on UDP {port} (DTLS)");
            Ok(port)
        }

        /// Stop accepting *and* drop the connections that were accepted, because webrtc-util's
        /// listener owns the UDP socket and the demultiplexing loop that feeds packets to
        /// already-accepted connections: dropping the listener without dropping those connections
        /// would leave them half-dead (they could still send, but never receive).
        async fn stop_listener_inner(&mut self) -> Result<()> {
            let Some(listener) = self.listener.take() else {
                return Ok(());
            };
            listener.task.abort();
            log::info!("listener on port {} stopped", listener.port);

            let inbound: Vec<SocketAddr> = self
                .peers
                .iter()
                .filter(|(_, p)| p.inbound)
                .map(|(addr, _)| *addr)
                .collect();
            for addr in inbound {
                if let Some(peer) = self.peers.remove(&addr) {
                    if peer.injecting {
                        self.release_injected();
                    }
                    let _ = self
                        .send_to(
                            &peer.conn,
                            ProtoEvent::Input(InputEvent::DeviceDisconnect {
                                reason: DisconnectReason::RemoteRequest,
                            }),
                        )
                        .await;
                    let _ = peer.conn.close().await;
                    log::info!("dropped inbound connection from {addr}");
                }
            }
            Ok(())
        }

        fn authorize_inner(&mut self, hex: &str, allow: bool) -> Result<()> {
            let fp = transport::parse_fingerprint_hex(hex)
                .ok_or_else(|| InputError::Network(format!("invalid fingerprint: {hex}")))?;
            match self.authorized.write() {
                Ok(mut set) => {
                    if allow {
                        set.insert(fp);
                    } else {
                        set.remove(&fp);
                    }
                }
                Err(_) => return Err(InputError::Network("authorization lock poisoned".into())),
            }
            log::info!(
                "peer {} {}",
                transport::fingerprint_hex(&fp),
                if allow { "authorized" } else { "revoked" }
            );
            Ok(())
        }

        async fn shutdown_inner(&mut self) {
            if self.forwarding {
                let _ = self.disable_forwarding().await;
            }
            self.release_injected();
            let _ = self.stop_capture_inner().await;
            let _ = self.stop_listener_inner().await;
            for (addr, peer) in self.peers.drain() {
                let _ = peer.conn.close().await;
                log::debug!("closed {addr}");
            }
            if let Some(emulator) = self.emulator.take() {
                emulator.shutdown();
            }
            log::info!("engine stopped");
        }
    }

    async fn accept_loop(listener: transport::BoxedListener, tx: mpsc::Sender<Incoming>) {
        loop {
            match listener.accept().await {
                Ok((conn, addr)) => {
                    log::info!("incoming connection from {addr}");
                    if tx.send(Incoming { conn, addr }).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    // A single failed handshake (wrong fingerprint, timeout, ...) must not kill the
                    // listener; upstream retries the same way.
                    log::debug!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    impl Engine {
        // -- local capture events -------------------------------------------------------------

        async fn on_local_event(&mut self, event: InputEvent) {
            let mut outgoing = EventBuf::new();
            match event {
                InputEvent::KeyboardKeyDown { key, time } => {
                    if key == keymap::KEY_LEFTMETA || key == keymap::KEY_RIGHTMETA {
                        self.hotkey_held = self.local_keys.is_empty();
                    } else {
                        self.hotkey_held = false;
                        self.reset_super_hotkey();
                    }
                    // Duplicate press: never forward it, it would desynchronise the peer.
                    if !self.local_keys.insert(key) {
                        log::debug!("ignoring duplicate key-down {key}");
                        return;
                    }
                    if key == keymap::KEY_LEFTMETA || key == keymap::KEY_RIGHTMETA {
                        return;
                    }
                    if self.mods.update(key, true) {
                        outgoing.push(self.modifier_event());
                    }
                    outgoing.push(InputEvent::KeyboardKeyDown { key, time });
                    if self.release_bind_held() {
                        log::warn!("release chord pressed: dropping control and releasing all keys");
                        self.forwarding = false;
                        self.forwarding_flag.store(false, Ordering::SeqCst);
                        if let Some(capture) = &self.capture {
                            capture.set_forwarding(false);
                        }
                        self.release_forwarded().await;
                        self.broadcast(
                            ProtoEvent::Input(InputEvent::DeviceDisconnect {
                                reason: DisconnectReason::ReleaseBind,
                            }),
                            false,
                        )
                        .await;
                        self.broadcast(ProtoEvent::Leave(0), false).await;
                        for peer in self.peers.values_mut() {
                            peer.forwarded = false;
                        }
                        return;
                    }
                }
                InputEvent::KeyboardKeyUp { key, time } => {
                    if key == keymap::KEY_LEFTMETA || key == keymap::KEY_RIGHTMETA {
                        if self.hotkey_held {
                            let now = Instant::now();
                            if let Some(last) = self.hotkey_last_release {
                                if now.duration_since(last) > Duration::from_millis(400) {
                                    self.hotkey_releases = 0;
                                }
                            }
                            self.hotkey_releases = self.hotkey_releases.saturating_add(1);
                            self.hotkey_last_release = Some(now);
                            self.hotkey_held = false;
                            if self.hotkey_releases >= 3 {
                                self.hotkey_releases = 0;
                                self.hotkey_last_release = None;
                                self.toggle_control_from_hotkey().await;
                            }
                        }
                        let _ = self.local_keys.remove(&key);
                        return;
                    }
                    if !self.local_keys.remove(&key) {
                        return;
                    }
                    if self.mods.update(key, false) {
                        outgoing.push(self.modifier_event());
                    }
                    outgoing.push(InputEvent::KeyboardKeyUp { key, time });
                }
                InputEvent::MouseButtonDown { button, time } => {
                    if !self.local_buttons.insert(button) {
                        return;
                    }
                    outgoing.push(InputEvent::MouseButtonDown { button, time });
                }
                InputEvent::MouseButtonUp { button, time } => {
                    if !self.local_buttons.remove(&button) {
                        return;
                    }
                    outgoing.push(InputEvent::MouseButtonUp { button, time });
                }
                InputEvent::MouseMove { .. }
                | InputEvent::MouseWheel { .. }
                | InputEvent::MouseScroll { .. } => outgoing.push(event),
                InputEvent::DeviceDisconnect { reason } => {
                    log::warn!("capture device lost ({reason:?}): releasing all keys");
                    self.release_forwarded().await;
                    self.broadcast(ProtoEvent::Input(event), false).await;
                    for peer in self.peers.values_mut() {
                        peer.forwarded = false;
                    }
                    self.forwarding = false;
                    self.forwarding_flag.store(false, Ordering::SeqCst);
                    return;
                }
                InputEvent::ModifierState { depressed, latched, locked, group } => {
                    self.mods.set(depressed, locked);
                    outgoing.push(InputEvent::ModifierState { depressed, latched, locked, group });
                }
                // A capture backend never produces StateSync; only the engine does.
                InputEvent::StateSync { .. } => return,
            }

            if !self.forwarding {
                return;
            }
            for ev in outgoing.iter() {
                self.broadcast(ProtoEvent::Input(*ev), true).await;
            }
        }

        fn modifier_event(&self) -> InputEvent {
            let mask = self.mods.mask();
            InputEvent::ModifierState {
                depressed: self.mods.pressed().bits(),
                latched: (mask & Modifiers::MOD3).bits(),
                locked: self.mods.locks().bits(),
                group: 0,
            }
        }

        fn release_bind_held(&self) -> bool {
            !self.cfg.release_bind.is_empty()
                && self.cfg.release_bind.iter().all(|k| self.local_keys.contains(k))
        }

        fn state_sync_event(&self) -> InputEvent {
            let mut buttons = 0u32;
            for button in &self.local_buttons {
                if *button >= proto::BTN_LEFT && *button < proto::BTN_LEFT + 5 {
                    buttons |= 1 << (*button - proto::BTN_LEFT);
                }
            }
            InputEvent::StateSync {
                seq: self.sync_seq,
                depressed: self.mods.pressed().bits(),
                locked: self.mods.locks().bits(),
                buttons,
                keys: KeySet::from_iter(self.local_keys.iter().copied()),
            }
        }

        /// Synthesise the key-up events the peer is missing, then re-send an empty state. This is
        /// what makes "no permanently stuck key" true even when the connection dies mid-chord.
        async fn release_forwarded(&mut self) {
            if self.local_keys.is_empty() && self.local_buttons.is_empty() {
                return;
            }
            let mut events: Vec<InputEvent> = Vec::with_capacity(self.local_keys.len() + 8);
            for key in self.local_keys.drain() {
                events.push(InputEvent::KeyboardKeyUp { key, time: 0 });
            }
            for button in self.local_buttons.drain() {
                events.push(InputEvent::MouseButtonUp { button, time: 0 });
            }
            events.push(InputEvent::ModifierState {
                depressed: 0,
                latched: 0,
                locked: 0,
                group: 0,
            });
            self.mods.reset();
            self.sync_seq = self.sync_seq.wrapping_add(1);
            events.push(self.state_sync_event());
            for event in events {
                self.broadcast(ProtoEvent::Input(event), true).await;
            }
        }

        // -- remote events --------------------------------------------------------------------

        async fn on_net(&mut self, msg: NetMsg) {
            match msg {
                NetMsg::Closed(addr) => {
                    if let Some(peer) = self.peers.remove(&addr) {
                        if peer.injecting {
                            log::warn!("{addr} disconnected while injecting: releasing keys");
                            self.release_injected();
                        }
                        log::info!("connection to {addr} closed");
                    }
                    if self.dialed == Some(addr) {
                        self.dialed = None;
                    }
                }
                NetMsg::Event(addr, event) => {
                    let Some(conn) = self.peers.get(&addr).map(|p| p.conn.clone()) else {
                        return;
                    };
                    if let Some(peer) = self.peers.get_mut(&addr) {
                        peer.last_rx = Instant::now();
                    }
                    match event {
                        ProtoEvent::Hello(version) => {
                            if let Some(peer) = self.peers.get_mut(&addr) {
                                peer.handshake = true;
                            }
                            if version != proto::PROTOCOL_VERSION {
                                log::info!(
                                    "peer {addr} runs build {}",
                                    String::from_utf8_lossy(&version)
                                );
                            }
                            log::info!("handshake with {addr} complete");
                        }
                        ProtoEvent::Ping => {
                            let can_inject = !self.cfg.accept_remote_input
                                || self.emulator.is_some()
                                || self.ensure_emulator();
                            self.send_to(&conn, ProtoEvent::Pong(can_inject)).await;
                        }
                        ProtoEvent::Pong(alive) => {
                            if let Some(peer) = self.peers.get_mut(&addr) {
                                if let Some(sent) = peer.last_ping.take() {
                                    peer.rtt_ms =
                                        Some(sent.elapsed().as_millis().min(u32::MAX as u128) as u32);
                                }
                            }
                            if !alive {
                                log::warn!("{addr} reports it cannot inject input");
                            }
                        }
                        ProtoEvent::Enter(direction) => {
                            self.on_enter(addr, conn, direction).await;
                        }
                        ProtoEvent::Leave(_) => {
                            let was_injecting =
                                self.peers.get(&addr).map(|p| p.injecting).unwrap_or(false);
                            if let Some(peer) = self.peers.get_mut(&addr) {
                                peer.injecting = false;
                            }
                            if was_injecting {
                                log::info!("{addr} left: releasing injected keys");
                                self.release_injected();
                            }
                        }
                        ProtoEvent::Ack(_) => {
                            if let Some(peer) = self.peers.get_mut(&addr) {
                                peer.forwarded = true;
                            }
                            log::info!("{addr} accepted control");
                        }
                        ProtoEvent::Input(event) => {
                            if !self.peers.get(&addr).map(|p| p.injecting).unwrap_or(false) {
                                log::debug!("dropping input from {addr}: no control granted");
                                return;
                            }
                            self.inject(event);
                        }
                    }
                }
            }
        }

        async fn on_enter(&mut self, addr: SocketAddr, conn: transport::ArcConn, dir: Direction) {
            if !self.cfg.accept_remote_input {
                log::warn!("{addr} requested control but accept_remote_input is false");
                return;
            }
            if !self.ensure_emulator() {
                // Do not ack: the peer must not believe it has control while nothing can be
                // injected. This is reported through ConnectionStatus::last_error.
                return;
            }
            // Only one peer may drive this machine; handing over control releases the previous one.
            let others: Vec<SocketAddr> = self
                .peers
                .iter()
                .filter(|(a, p)| **a != addr && p.injecting)
                .map(|(a, _)| *a)
                .collect();
            if !others.is_empty() {
                self.release_injected();
                for other in others {
                    if let Some(peer) = self.peers.get_mut(&other) {
                        peer.injecting = false;
                    }
                }
            }
            if let Some(peer) = self.peers.get_mut(&addr) {
                peer.injecting = true;
            }
            self.last_sync_seq = 0;
            log::info!("{addr} entered from {dir}: injecting its input");
            self.send_to(&conn, ProtoEvent::Ack(0)).await;
        }

        fn ensure_emulator(&mut self) -> bool {
            if self.emulator.is_some() {
                return true;
            }
            match EmulatorHandle::spawn(&self.cfg.device_name) {
                Ok(emulator) => {
                    self.emulator = Some(emulator);
                    self.last_error = None;
                    true
                }
                Err(e) => {
                    log::error!("cannot inject remote input: {e}");
                    self.last_error = Some(e.to_string());
                    false
                }
            }
        }

        // -- injection ------------------------------------------------------------------------

        fn inject(&mut self, event: InputEvent) {
            match event {
                InputEvent::KeyboardKeyDown { key, .. } => {
                    if !self.remote_keys.insert(key) {
                        return;
                    }
                }
                InputEvent::KeyboardKeyUp { key, .. } => {
                    if !self.remote_keys.remove(&key) {
                        return;
                    }
                }
                InputEvent::MouseButtonDown { button, .. } => {
                    if !self.remote_buttons.insert(button) {
                        return;
                    }
                }
                InputEvent::MouseButtonUp { button, .. } => {
                    if !self.remote_buttons.remove(&button) {
                        return;
                    }
                }
                InputEvent::StateSync { seq, keys, buttons, depressed, locked } => {
                    self.reconcile(seq, keys, buttons, depressed, locked);
                    return;
                }
                InputEvent::DeviceDisconnect { reason } => {
                    log::warn!("peer reported device loss ({reason:?}): releasing injected keys");
                    self.release_injected();
                    return;
                }
                _ => {}
            }
            if let Some(emulator) = &self.emulator {
                emulator.send(EmuCommand::Event(event));
            }
        }

        /// Converge the local injection state onto the sender's authoritative snapshot.
        fn reconcile(&mut self, seq: u32, keys: KeySet, buttons: u32, depressed: u32, locked: u32) {
            if self.last_sync_seq != 0 && seq.wrapping_sub(self.last_sync_seq) >= 0x8000_0000 {
                return; // stale snapshot, a newer one already arrived
            }
            self.last_sync_seq = seq;

            let target: HashSet<u32> = keys.iter().collect();
            let to_release: Vec<u32> = self.remote_keys.difference(&target).copied().collect();
            let to_press: Vec<u32> = target.difference(&self.remote_keys).copied().collect();
            let button_release: Vec<u32> = self
                .remote_buttons
                .iter()
                .copied()
                .filter(|b| {
                    let idx = b.wrapping_sub(proto::BTN_LEFT);
                    idx >= 5 || buttons & (1 << idx) == 0
                })
                .collect();

            let Some(emulator) = &self.emulator else { return };
            for key in to_release {
                self.remote_keys.remove(&key);
                log::debug!("state sync: releasing key {key}");
                emulator.send(EmuCommand::Event(InputEvent::KeyboardKeyUp { key, time: 0 }));
            }
            for key in to_press {
                self.remote_keys.insert(key);
                log::debug!("state sync: pressing key {key}");
                emulator.send(EmuCommand::Event(InputEvent::KeyboardKeyDown { key, time: 0 }));
            }
            for button in button_release {
                self.remote_buttons.remove(&button);
                emulator.send(EmuCommand::Event(InputEvent::MouseButtonUp { button, time: 0 }));
            }
            for idx in 0..5u32 {
                let button = proto::BTN_LEFT + idx;
                if buttons & (1 << idx) != 0 && self.remote_buttons.insert(button) {
                    emulator.send(EmuCommand::Event(InputEvent::MouseButtonDown {
                        button,
                        time: 0,
                    }));
                }
            }
            emulator.send(EmuCommand::Event(InputEvent::ModifierState {
                depressed,
                latched: 0,
                locked,
                group: 0,
            }));
        }

        fn release_injected(&mut self) {
            if let Some(emulator) = &self.emulator {
                emulator.send(EmuCommand::ReleaseAll);
            }
            self.remote_keys.clear();
            self.remote_buttons.clear();
            self.last_sync_seq = 0;
        }

        // -- incoming connections and timers --------------------------------------------------

        async fn on_incoming(&mut self, incoming: Incoming) {
            if let Some(old) = self.peers.remove(&incoming.addr) {
                let _ = old.conn.close().await;
            }
            self.peers.insert(
                incoming.addr,
                Peer {
                    conn: incoming.conn.clone(),
                    inbound: true,
                    handshake: false,
                    forwarded: false,
                    injecting: false,
                    last_rx: Instant::now(),
                    last_ping: None,
                    rtt_ms: None,
                },
            );
            self.spawn_reader(incoming.addr, incoming.conn.clone());
            self.send_to(&incoming.conn, ProtoEvent::Hello(proto::PROTOCOL_VERSION))
                .await;
        }

        async fn on_tick(&mut self) {
            self.tick_count = self.tick_count.wrapping_add(1);
            let now = Instant::now();

            // 1. Dead peers: release whatever they were holding before dropping the connection.
            let dead: Vec<SocketAddr> = self
                .peers
                .iter()
                .filter(|(_, p)| now.duration_since(p.last_rx) > self.cfg.idle_timeout)
                .map(|(addr, _)| *addr)
                .collect();
            for addr in dead {
                log::warn!("peer {addr} timed out");
                if let Some(peer) = self.peers.remove(&addr) {
                    if peer.injecting {
                        self.release_injected();
                    }
                    if self.dialed == Some(addr) {
                        self.dialed = None;
                    }
                    let _ = peer.conn.close().await;
                }
            }

            // 2. Liveness probes.
            if now.duration_since(self.last_ping) >= self.cfg.ping_interval {
                self.last_ping = now;
                for peer in self.peers.values_mut() {
                    peer.last_ping = Some(now);
                }
                self.broadcast(ProtoEvent::Ping, false).await;
            }

            // 3. Authoritative state, so a lost key-up cannot stick for longer than one interval.
            if self.forwarding && now.duration_since(self.last_sync) >= self.cfg.sync_interval {
                self.last_sync = now;
                self.sync_seq = self.sync_seq.wrapping_add(1);
                let event = self.state_sync_event();
                self.broadcast(ProtoEvent::Input(event), true).await;
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------------------------

    /// Handle to the running engine. Cheap to clone? No — one handle per engine; the methods take
    /// `&self` so a handle can be shared behind an `Arc`.
    pub struct RemoteInput {
        cmd: mpsc::Sender<Command>,
        task: tokio::task::JoinHandle<()>,
        status: Arc<StdMutex<ConnectionStatus>>,
    }

    impl RemoteInput {
        /// Start the engine. Must be called from inside a Tokio runtime.
        pub fn new(cfg: Config) -> Result<Self> {
            let handle = tokio::runtime::Handle::try_current().map_err(|_| {
                InputError::NotRunning
            })?;
            let identity = transport::Identity::generate()?;
            let status = Arc::new(StdMutex::new(ConnectionStatus {
                local_fingerprint: transport::fingerprint_hex(&identity.fingerprint),
                ..Default::default()
            }));
            let (cmd_tx, cmd_rx) = mpsc::channel(32);
            let (cap_tx, cap_rx) = mpsc::channel(CAP_CHANNEL);
            let (net_tx, net_rx) = mpsc::channel(1024);
            let (inc_tx, inc_rx) = mpsc::channel(16);
            let engine = Engine::new(cfg, identity, status.clone(), cap_tx, net_tx, inc_tx);
            let task = handle.spawn(engine.run(cmd_rx, cap_rx, net_rx, inc_rx));
            Ok(Self { cmd: cmd_tx, task, status })
        }

        async fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Result<T> {
            let (tx, rx) = oneshot::channel();
            self.cmd.send(make(tx)).await.map_err(|_| InputError::NotRunning)?;
            rx.await.map_err(|_| InputError::NotRunning)?
        }

        /// Start local input capture. Passive: local input is still delivered to this machine
        /// until [`RemoteInput::enable_remote_input`] grabs it (Linux) / swallows it (macOS).
        pub async fn start_capture(&self) -> Result<()> {
            self.call(Command::StartCapture).await
        }

        /// Stop capture and release everything that is currently held.
        pub async fn stop_capture(&self) -> Result<()> {
            self.call(Command::StopCapture).await
        }

        /// Dial a peer over UDP+DTLS. `host` may be a host name; every resolved address is tried
        /// in parallel and the first completed handshake wins.
        pub async fn connect_remote(&self, host: &str, port: u16) -> Result<()> {
            let host = host.to_string();
            self.call(move |reply| Command::Connect { host, port, reply }).await
        }

        /// Close the connection created by [`RemoteInput::connect_remote`].
        pub async fn disconnect_remote(&self) -> Result<()> {
            self.call(Command::Disconnect).await
        }

        /// Start sending local input to the connected peers (requires capture).
        pub async fn enable_remote_input(&self) -> Result<()> {
            self.call(|reply| Command::SetForwarding { on: true, reply }).await
        }

        /// Stop sending local input and release every key the peers still hold.
        pub async fn disable_remote_input(&self) -> Result<()> {
            self.call(|reply| Command::SetForwarding { on: false, reply }).await
        }

        /// Release every key and button on both sides of the connection.
        pub async fn release_all_inputs(&self) -> Result<()> {
            self.call(Command::ReleaseAll).await
        }

        /// Snapshot of the engine state. Never blocks on I/O.
        pub fn get_connection_status(&self) -> ConnectionStatus {
            match self.status.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        /// Start accepting peers (UDP+DTLS with client-certificate authentication).
        pub async fn start_listener(&self) -> Result<u16> {
            self.call(Command::StartListener).await
        }

        pub async fn stop_listener(&self) -> Result<()> {
            self.call(Command::StopListener).await
        }

        /// Add a peer fingerprint to the allow-list of the listener (hex, colons optional).
        pub async fn authorize_peer(&self, fingerprint_hex: &str) -> Result<()> {
            let fingerprint = fingerprint_hex.to_string();
            self.call(move |reply| Command::Authorize { fingerprint, allow: true, reply })
                .await
        }

        /// Remove a peer fingerprint. Affects new handshakes only.
        pub async fn revoke_peer(&self, fingerprint_hex: &str) -> Result<()> {
            let fingerprint = fingerprint_hex.to_string();
            self.call(move |reply| Command::Authorize { fingerprint, allow: false, reply })
                .await
        }

        /// This instance's own fingerprint, to be authorized on the peer side.
        pub fn local_fingerprint(&self) -> String {
            self.get_connection_status().local_fingerprint
        }

        /// Stop the engine, releasing all input and closing every connection.
        pub async fn shutdown(self) {
            let (tx, rx) = oneshot::channel();
            if self.cmd.send(Command::Shutdown(tx)).await.is_ok() {
                let _ = rx.await;
            }
            let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Tests: the parts that can be verified without touching an input device or a network.
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::keymap;
    use super::proto::{
        self, FrameType, InputEvent, KeySet, Modifiers, ProtocolError, ProtoEvent, MAX_FRAME_SIZE,
    };
    use super::transport;

    fn roundtrip(event: ProtoEvent) -> usize {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let n = proto::encode(&event, &mut buf);
        assert!(n <= MAX_FRAME_SIZE, "frame too large: {n}");
        let decoded = proto::decode(&buf[..n]).expect("frame must decode");
        assert_eq!(decoded, event, "roundtrip changed the event");
        n
    }

    #[test]
    fn keyboard_frame_matches_upstream_layout() {
        let event = ProtoEvent::Input(InputEvent::KeyboardKeyDown { key: 30, time: 0x0102_0304 });
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let n = proto::encode(&event, &mut buf);
        assert_eq!(n, 10);
        assert_eq!(buf[0], FrameType::KeyboardKey as u8);
        assert_eq!(&buf[1..5], &[0x01, 0x02, 0x03, 0x04]); // big-endian timestamp
        assert_eq!(&buf[5..9], &[0, 0, 0, 30]); // evdev code
        assert_eq!(buf[9], 1); // pressed
        roundtrip(event);
        roundtrip(ProtoEvent::Input(InputEvent::KeyboardKeyUp { key: 30, time: 0x0102_0304 }));
    }

    #[test]
    fn motion_frame_is_upstream_sized() {
        let n = roundtrip(ProtoEvent::Input(InputEvent::MouseMove { dx: 1.5, dy: -2.25, time: 7 }));
        // 1 byte id + 4 bytes time + 2 * 8 bytes delta = upstream's MAX_EVENT_SIZE (21).
        assert_eq!(n, 21);
    }

    #[test]
    fn pointer_frames_roundtrip() {
        roundtrip(ProtoEvent::Input(InputEvent::MouseButtonDown {
            button: proto::BTN_LEFT,
            time: 1,
        }));
        roundtrip(ProtoEvent::Input(InputEvent::MouseButtonUp { button: proto::BTN_BACK, time:  2 }));
        roundtrip(ProtoEvent::Input(InputEvent::MouseWheel {
            axis: proto::AXIS_VERTICAL,
            delta120: -240,
        }));
        roundtrip(ProtoEvent::Input(InputEvent::MouseScroll {
            axis: proto::AXIS_HORIZONTAL,
            pixels: -12.5,
            time: 3,
        }));
    }

    #[test]
    fn modifier_frame_roundtrip() {
        roundtrip(ProtoEvent::Input(InputEvent::ModifierState {
            depressed: (Modifiers::SHIFT | Modifiers::CONTROL).bits(),
            latched: 0,
            locked: Modifiers::LOCK.bits(),
            group: 0,
        }));
    }

    #[test]
    fn control_frames_roundtrip() {
        roundtrip(ProtoEvent::Ping);
        roundtrip(ProtoEvent::Pong(true));
        roundtrip(ProtoEvent::Pong(false));
        roundtrip(ProtoEvent::Enter(super::Direction::Left));
        roundtrip(ProtoEvent::Leave(0));
        roundtrip(ProtoEvent::Ack(42));
        roundtrip(ProtoEvent::Hello(proto::PROTOCOL_VERSION));
    }

    #[test]
    fn extension_frames_roundtrip() {
        roundtrip(ProtoEvent::Input(InputEvent::DeviceDisconnect {
            reason: super::DisconnectReason::DeviceLost,
        }));

        let keys = KeySet::from_iter([keymap::KEY_LEFTCTRL, 30, 31]);
        let event = ProtoEvent::Input(InputEvent::StateSync {
            seq: 9,
            depressed: Modifiers::CONTROL.bits(),
            locked: 0,
            buttons: 0b1,
            keys,
        });
        let n = roundtrip(event);
        // 1 + 4 + 4 + 4 + 4 + 1 + 3 * 4
        assert_eq!(n, 30);
    }

    #[test]
    fn truncated_frames_are_rejected() {
        assert!(matches!(proto::decode(&[]), Err(ProtocolError::Truncated { .. })));
        assert!(matches!(proto::decode(&[4, 0, 0]), Err(ProtocolError::Truncated { .. })));
        // Valid id, missing state byte.
        let short = [FrameType::KeyboardKey as u8, 0, 0, 0, 1, 0, 0, 0, 30];
        assert!(matches!(proto::decode(&short), Err(ProtocolError::Truncated { .. })));
    }

    #[test]
    fn unknown_and_oversized_frames_are_rejected() {
        assert_eq!(proto::decode(&[99, 0]), Err(ProtocolError::UnknownFrame(99)));
        let big = [0u8; MAX_FRAME_SIZE + 1];
        assert_eq!(proto::decode(&big), Err(ProtocolError::TooLarge(MAX_FRAME_SIZE + 1)));
    }

    #[test]
    fn invalid_axis_is_rejected() {
        let frame = [FrameType::PointerAxisValue120 as u8, 7, 0, 0, 0, 120];
        assert_eq!(proto::decode(&frame), Err(ProtocolError::InvalidValue("scroll axis", 7)));
    }

    #[test]
    fn modifier_tracker_follows_press_release_and_locks() {
        let mut tracker = keymap::ModifierTracker::new();
        assert!(tracker.update(keymap::KEY_LEFTSHIFT, true));
        assert_eq!(tracker.pressed(), Modifiers::SHIFT);
        assert!(!tracker.update(30, true), "a normal key must not change the mask");
        assert!(tracker.update(keymap::KEY_LEFTCTRL, true));
        assert_eq!(tracker.pressed(), Modifiers::SHIFT | Modifiers::CONTROL);
        assert!(tracker.update(keymap::KEY_LEFTSHIFT, false));
        assert_eq!(tracker.pressed(), Modifiers::CONTROL);
        assert!(tracker.update(keymap::KEY_LEFTCTRL, false));
        assert_eq!(tracker.mask(), Modifiers::empty());

        // Lock keys toggle on press and ignore their own release.
        assert!(tracker.update(keymap::KEY_CAPSLOCK, true));
        assert_eq!(tracker.locks(), Modifiers::LOCK);
        assert!(!tracker.update(keymap::KEY_CAPSLOCK, false));
        assert_eq!(tracker.locks(), Modifiers::LOCK);
        assert!(tracker.update(keymap::KEY_CAPSLOCK, true));
        assert_eq!(tracker.locks(), Modifiers::empty());
    }

    #[test]
    fn key_set_is_bounded_and_deduplicates() {
        let mut set = KeySet::new();
        for key in 0..proto::MAX_SYNC_KEYS as u32 {
            set.insert(key);
        }
        set.insert(3); // duplicate
        assert_eq!(set.len(), proto::MAX_SYNC_KEYS);
        set.insert(9999); // over capacity
        assert_eq!(set.len(), proto::MAX_SYNC_KEYS);
        assert!(set.truncated(proto::MAX_SYNC_KEYS + 1));
        assert!(set.contains(0) && !set.contains(9999));
    }

    #[test]
    fn key_codes_are_evdev() {
        // The protocol's canonical key code is the Linux evdev code.
        assert_eq!(keymap::KEY_ESC, 1);
        assert_eq!(keymap::KEY_LEFTCTRL, 29);
        assert_eq!(keymap::KEY_LEFTMETA, 125);
        assert_eq!(keymap::held_mask(keymap::KEY_LEFTMETA), Modifiers::MOD4);
        assert_eq!(keymap::lock_mask(keymap::KEY_CAPSLOCK), Modifiers::LOCK);
        assert!(keymap::is_modifier(keymap::KEY_LEFTALT));
        assert!(!keymap::is_modifier(30));
        assert_eq!(proto::BTN_LEFT, 0x110);
    }

    #[test]
    fn fingerprints_roundtrip_through_hex() {
        let fp = transport::fingerprint(b"remote-input");
        let hex = transport::fingerprint_hex(&fp);
        assert_eq!(hex.len(), 64);
        assert_eq!(transport::parse_fingerprint_hex(&hex), Some(fp));
        // Colons and upper case are accepted, as printed by `sha256sum`.
        let pretty = hex
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap().to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(transport::parse_fingerprint_hex(&pretty), Some(fp));
        assert_eq!(transport::parse_fingerprint_hex("deadbeef"), None);
    }

    #[test]
    fn event_buffer_never_allocates_past_capacity() {
        let mut buf = super::EventBuf::new();
        for _ in 0..16 {
            buf.push(InputEvent::MouseMove { dx: 1.0, dy: 1.0, time: 0 });
        }
        assert_eq!(buf.len(), 8);
        assert!(!buf.is_empty());
        buf.clear();
        assert!(buf.is_empty());
    }
}
