//! Shot notifications (cycle-31 close-out, council ruling (c)):
//! a Windows toast ONLY for alert-triggered shots and failures —
//! never for on-demand shots Yassin asked for himself, never during
//! game mode, and never carrying a window title or screen content.
//! A failed toast never fails the shot: the log stays the source of
//! truth, the toast is only a tap on the shoulder.

use std::path::PathBuf;

/// Outcome of a shot request, for the notify decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyOutcome {
    Taken,
    Failed,
}

/// Pure decision: should this shot produce a toast?
/// - alert:* taken → yes (unless gaming)
/// - on-demand taken → no (Yassin asked for it; he knows)
/// - any failure → yes (unless gaming) — a failure is data, and
///   silence about a dead shot path would hide a blind eye
/// - rate-limited → no (handled by the caller: no outcome given)
pub fn should_notify(reason: &str, outcome: NotifyOutcome, game_mode: bool) -> bool {
    if game_mode {
        return false;
    }
    match outcome {
        NotifyOutcome::Taken => reason.trim_start().starts_with("alert:"),
        NotifyOutcome::Failed => true,
    }
}

/// Pure toast text: event kind + nothing else. Takes no title and no
/// screen content as input, so none can ever leak into a toast.
pub fn toast_text(outcome: NotifyOutcome) -> String {
    match outcome {
        NotifyOutcome::Taken => "BIMO — لقطة تنبيه تمت".to_string(),
        NotifyOutcome::Failed => "BIMO — تعذّرت اللقطة".to_string(),
    }
}

/// Where toast attempts are recorded (best-effort): the self-test
/// reads this file to prove an attempt happened and what it returned.
pub fn probe_file(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("toast.probe")
}

fn record_probe(data_dir: &std::path::Path, ok: bool, error: &str) {
    let text = serde_json::json!({
        "attempted": true,
        "ok": ok,
        "error": error,
    })
    .to_string();
    let _ = std::fs::write(probe_file(data_dir), text);
}

/// Show the toast (Windows only) and record the probe. Never fails
/// the caller: returns the toast result; the caller logs it.
pub fn show_toast(data_dir: &std::path::Path, text: &str) -> Result<(), String> {
    let r = show_toast_inner(text);
    match &r {
        Ok(()) => record_probe(data_dir, true, ""),
        Err(e) => record_probe(data_dir, false, e),
    }
    r
}

// تشخيص الخطأ 0x80070490: CreateToastNotifier() من دون وسيط يتطلب AppUserModelID مسجلا لدى المتصل.
// وملف تنفيذي مكتبي غير معبأ يشغل مباشرة (كما على عداء CI) لا يملك واحدا،
// فيفشل بالخطأ 0x80070490 "Element not found". هذا ظرف بيئي على العداء،
// وليس خللا في XML التنبيه أو محتواه. اتجاه الإصلاح في يوم الوصول: ينشئ المثبت
// اختصارا في قائمة Start يحمل System.AppUserModel.ID، ويتحول الكود إلى CreateToastNotifier(appID) بنفس المعرف.
// الدليل: سجل eye-self-test-shots.json من التشغيل رقم 28: toast attempted: ok=false,
// error='CreateToastNotifier: Element not found. (0x80070490)'. وتوثق Microsoft Learn
// أن التحميل من دون وسيط يرمي الاستثناء من دون AppUserModelID صالح، وأنه يجب عدم استخدامه لتطبيقات سطح المكتب.
#[cfg(windows)]
fn show_toast_inner(text: &str) -> Result<(), String> {
    use windows::core::HSTRING;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    ensure_com();
    // `text` is a fixed literal from toast_text — never user input,
    // so no XML escaping is needed here.
    let xml = format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{text}</text></binding></visual></toast>"
    );
    let doc = XmlDocument::new().map_err(|e| format!("XmlDocument: {e}"))?;
    doc.LoadXml(&HSTRING::from(xml))
        .map_err(|e| format!("toast XML: {e}"))?;
    let toast = ToastNotification::CreateToastNotification(&doc)
        .map_err(|e| format!("CreateToastNotification: {e}"))?;
    let notifier = ToastNotificationManager::CreateToastNotifier()
        .map_err(|e| format!("CreateToastNotifier: {e}"))?;
    notifier.Show(&toast).map_err(|e| format!("toast Show: {e}"))?;
    Ok(())
}

#[cfg(not(windows))]
fn show_toast_inner(_text: &str) -> Result<(), String> {
    Err("toasts are Windows-only".to_string())
}

#[cfg(windows)]
fn ensure_com() {
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
    std::thread_local! {
        static COM_INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    COM_INIT.with(|c| {
        if !c.get() {
            let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            c.set(true);
        }
    });
}

#[cfg(not(windows))]
fn ensure_com() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_taken_notifies_on_demand_does_not() {
        assert!(should_notify("alert:motion", NotifyOutcome::Taken, false));
        assert!(!should_notify("on-demand", NotifyOutcome::Taken, false));
        assert!(!should_notify("self-test", NotifyOutcome::Taken, false));
    }

    #[test]
    fn failure_notifies_but_never_while_gaming() {
        assert!(should_notify("alert:x", NotifyOutcome::Failed, false));
        assert!(should_notify("on-demand", NotifyOutcome::Failed, false));
        assert!(!should_notify("alert:x", NotifyOutcome::Taken, true));
        assert!(!should_notify("alert:x", NotifyOutcome::Failed, true));
    }

    #[test]
    fn toast_text_is_fixed_and_carries_no_input() {
        assert_eq!(
            toast_text(NotifyOutcome::Taken),
            "BIMO — لقطة تنبيه تمت"
        );
        assert_eq!(
            toast_text(NotifyOutcome::Failed),
            "BIMO — تعذّرت اللقطة"
        );
    }
}
