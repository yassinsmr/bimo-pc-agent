//! bimo-island — the Dynamic Island + Liquid Glass renderer.
//!
//! Windows target (the Legion): a top-center popup window drawn
//! with Direct2D (native, GPU-paced). The window is drawn ONLY
//! while an animation or state change is in flight; at rest it
//! presents one static frame and sleeps — same rule as Oyenza Studio
//! and DockSide ("draws nothing while nothing moves").
//!
//! Glass in v1: DWM glass frame (DwmExtendFrameIntoClientArea, full
//! frame) gives the real blur-behind through the compositor; Direct2D
//! draws the capsule fill + specular rim + avatar circle on top.
//! A D2D GaussianBlur effect pass (device-context rendering) is a
//! later refinement — the blur-behind here is the compositor's, which
//! is also what HyperLand relies on.
//!
//! On non-Windows hosts this crate compiles to a stub so the core
//! can be built, tested and measured on BIMO's Linux machine.

use bimo_core::{Event, IslandState};

/// Liquid Glass recipe, from Apple's HIG principles + the Windows
/// references (HyperLand v2.6, Oyenza Glass theme, DockSide):
///  1. Real blur-behind (DWM backdrop / Direct2D Gaussian blur),
///     strongest at the edges — refraction lives at the rim.
///  2. Specular rim: a bright 1px edge highlight, slightly stronger
///     on dark backgrounds (glass has no fill of its own).
///  3. Adaptive tint: ~35% dark dimming layer behind clear glass
///     when the content underneath is bright (HIG guidance).
///  4. Spring morph: island size animates with an iPhone-style
///     spring (overshoot on expand, firmer collapse).
///  5. Glass ONLY on the control layer (the island itself) — never
///     on content, never glass-on-glass.
///  6. Motion with a purpose: animation explains where the island
///     came from / what just happened; nothing decorative loops.
#[derive(Debug, Clone, Copy)]
pub struct GlassSpec {
    /// Gaussian blur radius behind the glass (px).
    pub blur_radius: f32,
    /// Dark dimming layer opacity behind clear glass (0.0–1.0).
    pub dim_opacity: f32,
    /// Specular rim brightness (0.0–1.0).
    pub rim_brightness: f32,
    /// Saturation boost of the blurred backdrop.
    pub saturation: f32,
}

impl Default for GlassSpec {
    fn default() -> Self {
        GlassSpec {
            blur_radius: 28.0, // HyperLand `$Liquid` default
            dim_opacity: 0.35, // Apple HIG guidance
            rim_brightness: 0.6,
            saturation: 1.4,
        }
    }
}

/// Island geometry per state. Resting = the reference screenshot:
/// avatar circle on top, glass "BIMO" pill below it.
#[derive(Debug, Clone, Copy)]
pub struct IslandGeometry {
    pub width: f32,
    pub height: f32,
    /// Avatar circle diameter (px) — 0 when the avatar is hidden.
    pub avatar_diameter: f32,
}

impl IslandGeometry {
    pub fn for_state(state: IslandState) -> Self {
        match state {
            IslandState::Resting => IslandGeometry { width: 120.0, height: 36.0, avatar_diameter: 56.0 },
            IslandState::Working => IslandGeometry { width: 220.0, height: 44.0, avatar_diameter: 56.0 },
            IslandState::Speaking => IslandGeometry { width: 260.0, height: 52.0, avatar_diameter: 64.0 },
            IslandState::Done => IslandGeometry { width: 200.0, height: 44.0, avatar_diameter: 56.0 },
            IslandState::Alert => IslandGeometry { width: 320.0, height: 72.0, avatar_diameter: 56.0 },
        }
    }

    fn lerp(a: IslandGeometry, b: IslandGeometry, t: f32) -> IslandGeometry {
        IslandGeometry {
            width: a.width + (b.width - a.width) * t,
            height: a.height + (b.height - a.height) * t,
            avatar_diameter: a.avatar_diameter + (b.avatar_diameter - a.avatar_diameter) * t,
        }
    }
}

/// Called by the core loop on every state change. On Windows this
/// drives the Direct2D window; elsewhere it is a no-op stub that
/// keeps the core measurable.
pub fn present(state: IslandState, _ev: &Event) {
    #[cfg(windows)]
    windows_impl::present(state);
    #[cfg(not(windows))]
    {
        let _ = state;
        // Stub: no window on Linux. Rendering is Windows-only.
    }
}

/// Windows proof-gate entry point. Runs the draw experiment and
/// returns the process exit code: 0 = gate passed, 1 = gate failed
/// (measurements outside budget), 2 = gate could not run (no window
/// / no D2D). The JSON report goes to stdout and, when given, to a file.
#[cfg(windows)]
pub fn run_gate(out_path: Option<&str>) -> i32 {
    windows_impl::run_gate(out_path)
}

#[cfg(not(windows))]
pub fn run_gate(_out_path: Option<&str>) -> i32 {
    eprintln!("gate requires a real Windows host (use the GitHub Actions workflow)");
    3
}

#[cfg(windows)]
mod windows_impl {
    use super::{GlassSpec, IslandGeometry, IslandState};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    use windows::core::w;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::Graphics::Direct2D::Common::*;
    use windows::Win32::Graphics::Direct2D::*;
    use windows::Win32::Graphics::Dwm::DwmExtendFrameIntoClientArea;
    use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_UNKNOWN;
    use windows::Win32::Graphics::Gdi::UpdateWindow;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    use windows::Win32::UI::Controls::MARGINS;
    use windows::Win32::UI::WindowsAndMessaging::*;

    const WIN_W: i32 = 400;
    const WIN_H: i32 = 120;
    const CLASS_NAME: windows::core::PCWSTR = w!("BimoIsland");

    // Performance budget for the gate (starting thresholds — [مستنتجة],
    // to be ratified against the real Legion, not Apple numbers):
    // idle CPU < 1% (one core), idle RSS < 100 MB, morph >= 50 fps,
    // morph CPU < 25% (one core) during continuous animation.
    const IDLE_CPU_MAX_PCT: f64 = 1.0;
    const IDLE_RSS_MAX_MB: f64 = 100.0;
    const MORPH_FPS_MIN: f64 = 50.0;
    const MORPH_CPU_MAX_PCT: f64 = 25.0;

    struct Renderer {
        // Kept for future resize/recreate; the render target owns the
        // live HWND reference today.
        _hwnd: HWND,
        target: ID2D1HwndRenderTarget,
        fill_brush: ID2D1SolidColorBrush,
        rim_brush: ID2D1SolidColorBrush,
        avatar_brush: ID2D1SolidColorBrush,
        dwm_glass: bool,
    }

    static RENDERER: OnceLock<Mutex<Option<Renderer>>> = OnceLock::new();

    // COM interfaces wrap raw pointers: the renderer lives on the
    // main thread only (gate + present both run there).
    unsafe impl Send for Renderer {}

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_DESTROY {
            PostQuitMessage(0);
            return LRESULT(0);
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    fn pump_messages() {
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    impl Renderer {
        fn create() -> Result<Renderer, String> {
            unsafe {
                let hinstance = windows::Win32::Foundation::HINSTANCE(
                    GetModuleHandleW(None).map_err(|e| format!("GetModuleHandleW: {e}"))?.0,
                );
                let wc = WNDCLASSW {
                    style: CS_HREDRAW | CS_VREDRAW,
                    lpfnWndProc: Some(wnd_proc),
                    hInstance: hinstance,
                    lpszClassName: CLASS_NAME,
                    ..Default::default()
                };
                if RegisterClassW(&wc) == 0 {
                    return Err("RegisterClassW failed".into());
                }
                let screen_w = GetSystemMetrics(SM_CXSCREEN);
                let x = (screen_w - WIN_W) / 2;
                let hwnd = CreateWindowExW(
                    WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                    CLASS_NAME,
                    w!("BIMO"),
                    WS_POPUP,
                    x,
                    12,
                    WIN_W,
                    WIN_H,
                    None,
                    None,
                    Some(hinstance),
                    None,
                )
                .map_err(|e| format!("CreateWindowExW: {e}"))?;

                // Full-frame DWM glass: the compositor blurs the
                // backdrop behind the whole window (real blur-behind).
                let margins = MARGINS {
                    cxLeftWidth: -1,
                    cxRightWidth: -1,
                    cyTopHeight: -1,
                    cyBottomHeight: -1,
                };
                let dwm_glass = DwmExtendFrameIntoClientArea(hwnd, &margins).is_ok();

                let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                let _ = UpdateWindow(hwnd);

                let factory = D2D1CreateFactory::<ID2D1Factory>(
                    D2D1_FACTORY_TYPE_SINGLE_THREADED,
                    None,
                )
                .map_err(|e| format!("D2D1CreateFactory: {e}"))?;
                let rt_props = D2D1_RENDER_TARGET_PROPERTIES {
                    r#type: D2D1_RENDER_TARGET_TYPE_DEFAULT,
                    pixelFormat: D2D1_PIXEL_FORMAT {
                        format: DXGI_FORMAT_UNKNOWN,
                        alphaMode: D2D1_ALPHA_MODE_PREMULTIPLIED,
                    },
                    dpiX: 0.0,
                    dpiY: 0.0,
                    usage: D2D1_RENDER_TARGET_USAGE_NONE,
                    minLevel: D2D1_FEATURE_LEVEL_DEFAULT,
                };
                let hwnd_props = D2D1_HWND_RENDER_TARGET_PROPERTIES {
                    hwnd,
                    pixelSize: D2D_SIZE_U { width: WIN_W as u32, height: WIN_H as u32 },
                    presentOptions: D2D1_PRESENT_OPTIONS_NONE,
                };
                let target = factory
                    .CreateHwndRenderTarget(&rt_props, &hwnd_props)
                    .map_err(|e| format!("CreateHwndRenderTarget: {e}"))?;
                target.SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);

                let spec = GlassSpec::default();
                let fill_brush = target
                    .CreateSolidColorBrush(
                        &D2D1_COLOR_F { r: 1.0, g: 1.0, b: 1.0, a: 0.16 },
                        None,
                    )
                    .map_err(|e| format!("fill brush: {e}"))?;
                let rim_brush = target
                    .CreateSolidColorBrush(
                        &D2D1_COLOR_F { r: 1.0, g: 1.0, b: 1.0, a: spec.rim_brightness },
                        None,
                    )
                    .map_err(|e| format!("rim brush: {e}"))?;
                let avatar_brush = target
                    .CreateSolidColorBrush(
                        &D2D1_COLOR_F { r: 0.25, g: 0.55, b: 1.0, a: 1.0 },
                        None,
                    )
                    .map_err(|e| format!("avatar brush: {e}"))?;

                Ok(Renderer { _hwnd: hwnd, target, fill_brush, rim_brush, avatar_brush, dwm_glass })
            }
        }

        fn draw(&self, geo: IslandGeometry) -> Result<(), String> {
            unsafe {
                self.target.BeginDraw();
                let clear = D2D1_COLOR_F { r: 0.0, g: 0.0, b: 0.0, a: 0.0 };
                self.target.Clear(Some(&clear));
                // Pill: bottom-anchored, centered, capsule radius.
                let left = (WIN_W as f32 - geo.width) / 2.0;
                let top = WIN_H as f32 - 10.0 - geo.height;
                let pill = D2D1_ROUNDED_RECT {
                    rect: D2D_RECT_F {
                        left,
                        top,
                        right: left + geo.width,
                        bottom: top + geo.height,
                    },
                    radiusX: geo.height / 2.0,
                    radiusY: geo.height / 2.0,
                };
                self.target.FillRoundedRectangle(&pill, &self.fill_brush);
                self.target.DrawRoundedRectangle(&pill, &self.rim_brush, 1.0, None);
                // Avatar circle above the pill (reference screenshot).
                let d = geo.avatar_diameter;
                let mut avatar = D2D1_ELLIPSE::default();
                avatar.point.X = WIN_W as f32 / 2.0;
                avatar.point.Y = d / 2.0 + 6.0;
                avatar.radiusX = d / 2.0;
                avatar.radiusY = d / 2.0;
                self.target.FillEllipse(&avatar, &self.avatar_brush);
                self.target
                    .EndDraw(None, None)
                    .map_err(|e| format!("EndDraw: {e}"))?;
                Ok(())
            }
        }
    }

    fn renderer() -> &'static Mutex<Option<Renderer>> {
        RENDERER.get_or_init(|| Mutex::new(None))
    }

    pub fn present(state: IslandState) {
        let mut slot = match renderer().lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if slot.is_none() {
            match Renderer::create() {
                Ok(r) => *slot = Some(r),
                Err(e) => {
                    eprintln!("[island] renderer unavailable: {e}");
                    return;
                }
            }
        }
        if let Some(r) = slot.as_ref() {
            let geo = IslandGeometry::for_state(state);
            if let Err(e) = r.draw(geo) {
                eprintln!("[island] draw failed: {e}");
            }
        }
    }

    // ---- measurement helpers ----

    fn sample_process() -> (u64, u64) {
        // Returns (working-set bytes, total CPU time in 100ns units).
        unsafe {
            let h = GetCurrentProcess();
            let mut mem = PROCESS_MEMORY_COUNTERS_EX::default();
            mem.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            let rss = if GetProcessMemoryInfo(
                h,
                &mut mem as *mut PROCESS_MEMORY_COUNTERS_EX
                    as *mut windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS,
                mem.cb,
            )
            .is_ok() {
                mem.WorkingSetSize as u64
            } else {
                0
            };
            let mut _creation = windows::Win32::Foundation::FILETIME::default();
            let mut _exit = windows::Win32::Foundation::FILETIME::default();
            let mut kernel = windows::Win32::Foundation::FILETIME::default();
            let mut user = windows::Win32::Foundation::FILETIME::default();
            let cpu = if GetProcessTimes(h, &mut _creation, &mut _exit, &mut kernel, &mut user)
                .is_ok()
            {
                let k = ((kernel.dwHighDateTime as u64) << 32) | kernel.dwLowDateTime as u64;
                let u = ((user.dwHighDateTime as u64) << 32) | user.dwLowDateTime as u64;
                k + u
            } else {
                0
            };
            (rss, cpu)
        }
    }

    fn cpu_pct(cpu0: u64, cpu1: u64, wall: Duration) -> f64 {
        if wall.is_zero() {
            return 0.0;
        }
        let delta_100ns = cpu1.saturating_sub(cpu0) as f64;
        let wall_100ns = wall.as_secs_f64() * 10_000_000.0;
        delta_100ns / wall_100ns * 100.0
    }

    /// The gate experiment. Prints the JSON report to stdout.
    pub fn run_gate(out_path: Option<&str>) -> i32 {
        let spec = GlassSpec::default();
        let resting = IslandGeometry::for_state(IslandState::Resting);
        let working = IslandGeometry::for_state(IslandState::Working);

        let mut renderer = match Renderer::create() {
            Ok(r) => r,
            Err(e) => {
                let json = format!(
                    "{{\"gate\":\"error\",\"reason\":\"renderer creation failed: {}\"}}",
                    e.replace('"', "'")
                );
                println!("{json}");
                return 2;
            }
        };
        let dwm_glass = renderer.dwm_glass;
        if renderer.draw(resting).is_err() {
            println!("{{\"gate\":\"error\",\"reason\":\"first draw failed\"}}");
            return 2;
        }

        // Phase A — idle 60 s: one static frame, then nothing.
        let mut rss_min = u64::MAX;
        let mut rss_max = 0u64;
        let mut rss_sum = 0u64;
        let idle_start = Instant::now();
        let (_rss0, cpu0) = sample_process();
        for _ in 0..60 {
            std::thread::sleep(Duration::from_secs(1));
            pump_messages();
            let (rss, _) = sample_process();
            if rss > 0 {
                rss_min = rss_min.min(rss);
                rss_max = rss_max.max(rss);
                rss_sum += rss;
            }
        }
        let idle_wall = idle_start.elapsed();
        let (rss1, cpu1) = sample_process();
        let idle_cpu = cpu_pct(cpu0, cpu1, idle_wall);
        let idle_rss_mean_kb = if rss_sum > 0 { rss_sum / 60 / 1024 } else { rss1 / 1024 };
        let idle_rss_min_kb = if rss_min == u64::MAX { 0 } else { rss_min / 1024 };
        let idle_rss_max_kb = rss_max / 1024;

        // Phase B — continuous morph 10 s: Resting <-> Working spring.
        let morph_start = Instant::now();
        let (_m_rss0, m_cpu0) = sample_process();
        let mut v: f32 = 0.0;
        let mut vel: f32 = 0.0;
        let mut target: f32 = 1.0;
        let mut last_switch = Instant::now();
        let mut frames: u64 = 0;
        let omega: f32 = 2.0 * std::f32::consts::PI / 0.5; // ~0.5 s response
        let k: f32 = omega * omega;
        let c: f32 = 2.0 * 0.8 * omega; // damping ~0.8
        let dt: f32 = 1.0 / 60.0;
        let mut draw_error: Option<String> = None;
        while morph_start.elapsed() < Duration::from_secs(10) {
            pump_messages();
            if last_switch.elapsed() > Duration::from_millis(700) {
                target = 1.0 - target;
                last_switch = Instant::now();
            }
            let accel = -k * (v - target) - c * vel;
            vel += accel * dt;
            v += vel * dt;
            let geo = IslandGeometry::lerp(resting, working, v.clamp(0.0, 1.0));
            match renderer.draw(geo) {
                Ok(()) => frames += 1,
                Err(e) => {
                    draw_error = Some(e);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(16));
        }
        let morph_wall = morph_start.elapsed();
        let (m_rss1, m_cpu1) = sample_process();
        let morph_cpu = cpu_pct(m_cpu0, m_cpu1, morph_wall);
        let morph_fps = frames as f64 / morph_wall.as_secs_f64();
        let morph_rss_kb = m_rss1 / 1024;
        let _ = &mut renderer;

        let pass = draw_error.is_none()
            && idle_cpu < IDLE_CPU_MAX_PCT
            && (idle_rss_max_kb as f64) < IDLE_RSS_MAX_MB * 1024.0
            && morph_fps >= MORPH_FPS_MIN
            && morph_cpu < MORPH_CPU_MAX_PCT;
        let gate = if pass { "pass" } else { "fail" };
        let json = format!(
            "{{\"gate\":\"{gate}\",\"dwm_glass\":{dwm_glass},\"glass\":{{\"blur_radius\":{},\"dim_opacity\":{},\"rim_brightness\":{},\"saturation\":{}}},\"idle\":{{\"seconds\":60,\"cpu_pct\":{idle_cpu:.2},\"rss_kb\":{{\"min\":{idle_rss_min_kb},\"mean\":{idle_rss_mean_kb},\"max\":{idle_rss_max_kb}}}}},\"morph\":{{\"seconds\":{:.1},\"frames\":{frames},\"fps\":{morph_fps:.1},\"cpu_pct\":{morph_cpu:.2},\"rss_kb\":{morph_rss_kb}}},\"draw_error\":{}}}",
            spec.blur_radius,
            spec.dim_opacity,
            spec.rim_brightness,
            spec.saturation,
            morph_wall.as_secs_f64(),
            match &draw_error {
                Some(e) => format!("\"{}\"", e.replace('"', "'")),
                None => "null".to_string(),
            }
        );
        println!("{json}");
        if let Some(path) = out_path {
            let _ = std::fs::write(path, &json);
        }
        if pass {
            0
        } else {
            1
        }
    }
}
