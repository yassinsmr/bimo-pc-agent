//! Screen capture for the eye unit (Windows only).
//!
//! Moves the spike's capture core (`apps/eye-shot-spike`, PR #9) into
//! the unit, with the two gaps the spike honestly recorded now closed:
//!
//! 1. **Persistent session (council binding point, cycle 27):** the
//!    aggregate measurement priced the WARM cost (13.75 ms/shot) on
//!    ONE session delivering 101 frames. That definition holds ONLY
//!    if the unit reuses one session the same way. `CaptureSession`
//!    therefore opens ONE Graphics Capture session and keeps it alive
//!    across shots; a shot is one frame out of that session. If the
//!    session cannot deliver a frame within 20 s, the service restarts
//!    it once (a cold shot) — and if the persistent session were ever
//!    replaced by per-shot sessions, the cost definition goes back to
//!    the council (the cold cost, 25 ms/shot, would apply instead).
//! 2. **JPEG quality 80 + max width 1920:** `windows-capture` 2.0.1
//!    exposes no quality setting and no resize (WIC default quality,
//!    full monitor width — the spike's honest deviation). This module
//!    re-encodes the raw RGBA buffer itself through WIC
//!    (`IWICImagingFactory` → optional scaler → JPEG encoder with the
//!    `ImageQuality` property bag set to 0.8). If the WIC path fails
//!    for any reason, the frame falls back to `windows-capture`'s own
//!    `save_as_image` and the event records `quality:
//!    "wic-default-fallback"` — a valid JPEG either way, and the
//!    difference is visible in the log, never hidden.
//!
//! Honest limits (same as the spike, carried over):
//! - The runner has no real display and no game: a no-frame timeout
//!   is recorded with `"no_screen": true` by the self-test and the
//!   verdict defers to the Legion. Capture over a real exclusive
//!   fullscreen game is NOT tested here (second gate, on arrival).
//! - Frames arrive only when the compositor has an update: on a
//!   static desktop a requested shot may wait (the spike measured
//!   125–541 ms waits). That wait is idle time (~0 CPU) and is
//!   recorded as `wait_ms`, never counted as cost.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// JPEG quality for unit shots (§1 of the shot spec: quality 80).
pub const JPEG_QUALITY: f32 = 0.8;
/// Max shot width (§1: 1920). Wider monitors are downscaled.
pub const MAX_WIDTH: u32 = 1920;
/// How long one requested shot waits for a frame before the session
/// is declared stale and restarted (spike watchdog: 20 s).
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(20);

/// What one completed shot produced.
#[derive(Debug, Clone)]
pub struct ShotInfo {
    pub file: PathBuf,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    /// `"80"` when the WIC path set the quality, `"wic-default-fallback"`
    /// when the encoder fell back to `windows-capture`'s default.
    pub quality: &'static str,
    /// True when this was the first frame of a (fresh) session — it
    /// carries the D3D device + session setup cost (the cold price).
    pub cold: bool,
    /// Wall time from the request to the frame's arrival (idle wait
    /// for the compositor on a static desktop; ~0 CPU).
    pub wait_ms: u128,
    /// Wall time of the JPEG encode itself.
    pub encode_ms: u128,
    /// Files pruned by the service after this shot (cycle 31):
    /// 0 at capture time; the service fills these in.
    pub pruned: u64,
    /// Bytes freed by that pruning.
    pub pruned_bytes: u64,
}

struct Pending {
    out_path: PathBuf,
    requested_at: Instant,
    reply: std::sync::mpsc::Sender<Result<ShotInfo, String>>,
}

/// State shared between the session thread (the handler) and the
/// requesting thread. The handler never blocks: on a frame it takes
/// the pending request if there is one, encodes, and replies.
struct SharedState {
    pending: Mutex<Option<Pending>>,
    /// Set by `CaptureSession::stop`; the handler stops the session
    /// on the next frame arrival.
    stop_requested: AtomicBool,
    /// Set when `start()` returns (session ended, clean or failed).
    ended: AtomicBool,
    /// Error that killed the session thread, if any (e.g. no monitor).
    start_error: Mutex<Option<String>>,
    /// Frames delivered by this session (first one is cold).
    delivered: AtomicUsize,
    /// Wakeups for `wait_until_ended` (used only by `stop`).
    /// Has its own mutex: `stop()` must NOT hold the `pending` lock
    /// while waiting, or the handler could never take `pending` to
    /// notice the stop flag.
    ended_lock: Mutex<()>,
    ended_cv: Condvar,
}

impl SharedState {
    fn new() -> Self {
        SharedState {
            pending: Mutex::new(None),
            stop_requested: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            start_error: Mutex::new(None),
            delivered: AtomicUsize::new(0),
            ended_lock: Mutex::new(()),
            ended_cv: Condvar::new(),
        }
    }
}

/// One persistent Graphics Capture session on the primary monitor.
pub struct CaptureSession {
    shared: Arc<SharedState>,
    /// The session thread is detached on purpose: `start()` blocks
    /// inside the capture runtime and can only exit on a frame
    /// arrival (stop flag) or a session error. `stop()` waits up to
    /// 5 s for it and then abandons it — a leaked idle thread on
    /// shutdown is documented and harmless; a hung eye stop is not.
    _thread: std::thread::JoinHandle<()>,
}

impl CaptureSession {
    /// Open a new session on the primary monitor. Returns once the
    /// session thread is spawned; the first frame proves the session
    /// works (a failed start surfaces as `start_error` on the first
    /// `request`).
    pub fn start_new() -> Self {
        let shared = Arc::new(SharedState::new());
        let thread_shared = shared.clone();
        let handle = std::thread::spawn(move || {
            session_thread(thread_shared);
        });
        CaptureSession {
            shared,
            _thread: handle,
        }
    }

    /// Request one shot. Exactly one request may be pending at a
    /// time (the service serialises callers); a second concurrent
    /// request is refused rather than queued.
    pub fn request(&self, out_path: &Path) -> Result<ShotInfo, String> {
        if self.shared.ended.load(Ordering::SeqCst) {
            if let Some(e) = self.shared.start_error.lock().ok().and_then(|g| g.clone()) {
                return Err(format!("capture session ended: {e}"));
            }
            return Err("capture session ended".to_string());
        }
        let (tx, rx) = std::sync::mpsc::channel::<Result<ShotInfo, String>>();
        {
            let mut pending = self.shared.pending.lock().map_err(|_| "pending lock poisoned")?;
            if pending.is_some() {
                return Err("a shot is already pending on this session".to_string());
            }
            *pending = Some(Pending {
                out_path: out_path.to_path_buf(),
                requested_at: Instant::now(),
                reply: tx,
            });
        }
        match rx.recv_timeout(FRAME_TIMEOUT) {
            Ok(r) => r,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Clear the stale pending request so the next shot can
                // proceed (the session is restarted by the service).
                if let Ok(mut pending) = self.shared.pending.lock() {
                    *pending = None;
                }
                Err("no frame within 20 s (headless runner? static desktop?) — session stale, restart once".to_string())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("capture session ended while waiting for a frame".to_string())
            }
        }
    }

    /// Ask the session to stop on the next frame; wait up to 5 s,
    /// then give up waiting (the thread is abandoned, documented
    /// above — it holds no resources that matter at shutdown).
    pub fn stop(&self) {
        self.shared.stop_requested.store(true, Ordering::SeqCst);
        let guard = self
            .shared
            .ended_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _ = self
            .shared
            .ended_cv
            .wait_timeout(guard, Duration::from_secs(5));
    }

    pub fn frames_delivered(&self) -> usize {
        self.shared.delivered.load(Ordering::SeqCst)
    }

    pub fn is_alive(&self) -> bool {
        !self.shared.ended.load(Ordering::SeqCst)
    }
}

/// The session thread: opens the monitor, starts the capture loop,
/// and marks the session ended when `start()` returns.
fn session_thread(shared: Arc<SharedState>) {
    let result = run_session(&shared);
    if let Err(e) = result {
        if let Ok(mut g) = shared.start_error.lock() {
            *g = Some(e);
        }
    }
    shared.ended.store(true, Ordering::SeqCst);
    shared.ended_cv.notify_all();
}

#[cfg(windows)]
fn run_session(shared: &Arc<SharedState>) -> Result<(), String> {
    use windows_capture::capture::{Context, GraphicsCaptureApiHandler};
    use windows_capture::frame::Frame;
    use windows_capture::graphics_capture_api::InternalCaptureControl;
    use windows_capture::monitor::Monitor;
    use windows_capture::settings::{
        ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
        MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
    };

    struct SessionHandler {
        shared: Arc<SharedState>,
    }

    impl GraphicsCaptureApiHandler for SessionHandler {
        type Flags = Arc<SharedState>;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
            Ok(Self {
                shared: ctx.flags,
            })
        }

        fn on_frame_arrived(
            &mut self,
            frame: &mut Frame,
            capture_control: InternalCaptureControl,
        ) -> Result<(), Self::Error> {
            if self.shared.stop_requested.load(Ordering::SeqCst) {
                capture_control.stop();
                return Ok(());
            }
            let pending = {
                match self.shared.pending.lock() {
                    Ok(mut g) => g.take(),
                    Err(_) => None,
                }
            };
            let Some(p) = pending else {
                // No shot requested: ignore the frame. The session
                // stays alive; idle frames cost nothing but the
                // callback itself.
                return Ok(());
            };
            let wait_ms = p.requested_at.elapsed().as_millis();
            let cold = self.shared.delivered.fetch_add(1, Ordering::SeqCst) == 0;
            let enc0 = Instant::now();
            let result = encode_frame(frame, &p.out_path);
            let encode_ms = enc0.elapsed().as_millis();
            let info = match result {
                Ok((width, height, bytes, quality)) => Ok(ShotInfo {
                    file: p.out_path.clone(),
                    width,
                    height,
                    bytes,
                    quality,
                    cold,
                    wait_ms,
                    encode_ms,
                pruned: 0,
                pruned_bytes: 0,
                }),
                Err(e) => Err(e),
            };
            let _ = p.reply.send(info);
            Ok(())
        }

        fn on_closed(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    let monitor = Monitor::primary().map_err(|e| format!("Monitor::primary: {e}"))?;
    let settings = Settings::new(
        monitor,
        CursorCaptureSettings::Default,
        DrawBorderSettings::Default,
        SecondaryWindowSettings::Default,
        MinimumUpdateIntervalSettings::Default,
        DirtyRegionSettings::Default,
        ColorFormat::Rgba8,
        shared.clone(),
    );
    // Blocks until the handler calls capture_control.stop() (or the
    // session errors). This is the persistent session: it is NOT
    // stopped after the first frame.
    SessionHandler::start(settings).map_err(|e| format!("GraphicsCapture start: {e}"))?;
    Ok(())
}

#[cfg(not(windows))]
fn run_session(_shared: &Arc<SharedState>) -> Result<(), String> {
    Err("capture is Windows-only".to_string())
}

/// Encode one frame as JPEG (quality 80, max width 1920) via WIC.
/// Returns (width, height, bytes, quality). On any WIC failure the
/// caller falls back to `windows-capture`'s `save_as_image` — this
/// function returns the error so the fallback path stays visible.
#[cfg(windows)]
fn encode_frame(
    frame: &mut windows_capture::frame::Frame,
    out_path: &Path,
) -> Result<(u32, u32, u64, &'static str), String> {
    // COM must be initialised on the thread that creates WIC objects.
    // The capture callback may run on a WinRT thread where COM is
    // already initialised (then this returns S_FALSE / CHANGED_MODE
    // and is harmless); failure here does not abort — the WIC calls
    // below will fail cleanly and the caller falls back.
    ensure_com();
    let width = frame.width();
    let height = frame.height();
    let color_format = frame.color_format();
    let mut scratch = Vec::new();
    let fb = frame
        .buffer()
        .map_err(|e| format!("frame buffer: {e}"))?;
    let pixels = fb.as_nopadding_buffer(&mut scratch).to_vec();
    // Release the frame borrow BEFORE any fallback that needs `frame`
    // again (`save_as_image` takes `&mut Frame`).
    drop(fb);
    let stride = width
        .checked_mul(4)
        .ok_or_else(|| "frame width overflows stride".to_string())?;
    match wic_encode_jpeg(&pixels, width, height, stride, color_format, out_path) {
        Ok((w, h)) => {
            let bytes = std::fs::metadata(out_path).map(|m| m.len()).unwrap_or(0);
            Ok((w, h, bytes, "80"))
        }
        Err(wic_err) => {
            // Honest fallback: WIC default quality, full width — the
            // same output the spike produced. The event says so.
            eprintln!("[bimo-shot] WIC encode failed ({wic_err}); falling back to windows-capture default JPEG");
            frame
                .save_as_image(out_path, windows_capture::encoder::ImageFormat::Jpeg)
                .map_err(|e| format!("fallback save_as_image failed after WIC failure ({wic_err}): {e}"))?;
            let bytes = std::fs::metadata(out_path).map(|m| m.len()).unwrap_or(0);
            Ok((width, height, bytes, "wic-default-fallback"))
        }
    }
}

#[cfg(windows)]
fn ensure_com() {
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
    std::thread_local! {
        static COM_INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    COM_INIT.with(|c| {
        if !c.get() {
            // S_OK, S_FALSE (already initialised) and
            // RPC_E_CHANGED_MODE (already initialised differently)
            // are all "proceed": WIC will either work or fail
            // cleanly and the caller falls back.
            let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            c.set(true);
        }
    });
}

/// WIC encode: RGBA8/BGRA8 buffer → JPEG file, quality 0.8, width
/// capped at `MAX_WIDTH` (aspect preserved). Returns the written
/// (width, height).
#[cfg(windows)]
fn wic_encode_jpeg(
    pixels: &[u8],
    width: u32,
    height: u32,
    stride: u32,
    color_format: windows_capture::settings::ColorFormat,
    out_path: &Path,
) -> Result<(u32, u32), String> {
    use windows::Win32::Graphics::Imaging::{
        CLSID_WICImagingFactory, GUID_ContainerFormatJpeg, GUID_WICPixelFormat24bppBGR,
        GUID_WICPixelFormat32bppBGRA, GUID_WICPixelFormat32bppRGBA,
        IWICBitmapFrameEncode, IWICBitmapScaler, IWICImagingFactory, WICBitmapEncoderNoCache,
        WICBitmapInterpolationModeFant,
    };
    use windows::Win32::System::Com::StructuredStorage::IPropertyBag2;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
    use windows::core::{Interface, PCWSTR};
    use std::os::windows::ffi::OsStrExt;

    let expected = (stride as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| "frame buffer size overflows".to_string())?;
    if pixels.len() < expected {
        return Err(format!(
            "frame buffer too small: {} bytes for {}x{} stride {}",
            pixels.len(),
            width,
            height,
            stride
        ));
    }
    let (target_w, target_h) = if width > MAX_WIDTH {
        let scale = MAX_WIDTH as f64 / width as f64;
        (
            MAX_WIDTH,
            ((height as f64 * scale).round() as u32).max(1),
        )
    } else {
        (width, height)
    };
    let src_format = match color_format {
        windows_capture::settings::ColorFormat::Bgra8 => GUID_WICPixelFormat32bppBGRA,
        _ => GUID_WICPixelFormat32bppRGBA,
    };

    unsafe {
        let factory: IWICImagingFactory =
            CoCreateInstance(&CLSID_WICImagingFactory, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| format!("CoCreateInstance WIC factory: {e}"))?;
        let bitmap = factory
            .CreateBitmapFromMemory(width, height, &src_format, stride, pixels)
            .map_err(|e| format!("CreateBitmapFromMemory: {e}"))?;
        // Downscale first (if needed) so the encoder never sees a
        // wider-than-1920 source.
        let source: windows::Win32::Graphics::Imaging::IWICBitmapSource =
            if target_w != width {
                let scaler: IWICBitmapScaler = factory
                    .CreateBitmapScaler()
                    .map_err(|e| format!("CreateBitmapScaler: {e}"))?;
                scaler
                    .Initialize(&bitmap, target_w, target_h, WICBitmapInterpolationModeFant)
                    .map_err(|e| format!("scaler Initialize: {e}"))?;
                scaler.cast().map_err(|e| format!("scaler cast: {e}"))?
            } else {
                bitmap.cast().map_err(|e| format!("bitmap cast: {e}"))?
            };
        let stream = factory
            .CreateStream()
            .map_err(|e| format!("CreateStream: {e}"))?;
        let wide_path: Vec<u16> = out_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        stream
            .InitializeFromFilename(PCWSTR(wide_path.as_ptr()), 0x4000_0000 /* GENERIC_WRITE */)
            .map_err(|e| format!("stream InitializeFromFilename: {e}"))?;
        let encoder = factory
            .CreateEncoder(&GUID_ContainerFormatJpeg, std::ptr::null())
            .map_err(|e| format!("CreateEncoder JPEG: {e}"))?;
        encoder
            .Initialize(&stream, WICBitmapEncoderNoCache)
            .map_err(|e| format!("encoder Initialize: {e}"))?;
        // CreateNewFrame returns the frame AND the encoder-options
        // property bag (out params). The JPEG quality is set in that
        // bag BEFORE Initialize — the documented WIC pattern. If the
        // bag is missing, the quality claim would be a lie, so that
        // is an error here (the caller falls back and records
        // "wic-default-fallback" honestly).
        let mut frame_opt: Option<IWICBitmapFrameEncode> = None;
        let mut options_opt: Option<IPropertyBag2> = None;
        encoder
            .CreateNewFrame(&mut frame_opt, &mut options_opt)
            .map_err(|e| format!("CreateNewFrame: {e}"))?;
        let frame_encode = frame_opt.ok_or_else(|| "CreateNewFrame returned no frame".to_string())?;
        let options = options_opt
            .ok_or_else(|| "CreateNewFrame returned no encoder options bag".to_string())?;
        set_jpeg_quality(&options)?;
        frame_encode
            .Initialize(Some(&options))
            .map_err(|e| format!("frame Initialize: {e}"))?;
        let mut out_format = GUID_WICPixelFormat24bppBGR;
        frame_encode
            .SetSize(target_w, target_h)
            .map_err(|e| format!("frame SetSize: {e}"))?;
        frame_encode
            .SetPixelFormat(&mut out_format)
            .map_err(|e| format!("frame SetPixelFormat: {e}"))?;
        frame_encode
            .WriteSource(&source, std::ptr::null())
            .map_err(|e| format!("frame WriteSource: {e}"))?;
        frame_encode
            .Commit()
            .map_err(|e| format!("frame Commit: {e}"))?;
        encoder
            .Commit()
            .map_err(|e| format!("encoder Commit: {e}"))?;
    }
    Ok((target_w, target_h))
}

/// Set `ImageQuality = 0.8` in a JPEG encoder-options property bag.
#[cfg(windows)]
fn set_jpeg_quality(bag: &windows::Win32::System::Com::StructuredStorage::IPropertyBag2) -> Result<(), String> {
    use windows::Win32::System::Com::StructuredStorage::PROPBAG2;
    use windows::Win32::System::Variant::{VARIANT, VT_R4};
    use windows::core::PWSTR;

    // "ImageQuality" as a null-terminated wide string (static so the
    // PWSTR stays valid for the call).
    static NAME: &[u16] = &[
        'I' as u16, 'm' as u16, 'a' as u16, 'g' as u16, 'e' as u16, 'Q' as u16, 'u' as u16,
        'a' as u16, 'l' as u16, 'i' as u16, 't' as u16, 'y' as u16, 0,
    ];
    unsafe {
        let mut variant = VARIANT::default();
        // `Anonymous` is a `ManuallyDrop` union field: the explicit `*`
        // deref is required (the compiler refuses the implicit one).
        (*variant.Anonymous.Anonymous).vt = VT_R4;
        (*variant.Anonymous.Anonymous).Anonymous.fltVal = JPEG_QUALITY;
        let prop = PROPBAG2 {
            dwType: 1, // PROPBAG2_TYPE_DATA
            vt: VT_R4,
            cfType: 0,
            dwHint: 0,
            pstrName: PWSTR(NAME.as_ptr() as *mut u16),
            clsid: windows::core::GUID::zeroed(),
        };
        bag.Write(1, &prop, &variant)
            .map_err(|e| format!("property bag Write ImageQuality: {e}"))?;
    }
    Ok(())
}
