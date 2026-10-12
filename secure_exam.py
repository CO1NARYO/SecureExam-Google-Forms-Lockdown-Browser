# -*- coding: utf-8 -*-
"""
SecureExam - Google Forms lockdown browser (Python + PyQt5)

* Opens ONE Google Form in a fullscreen, always-on-top window.
* Detects focus loss (other app / tab / window / minimise) -> strike system.
* Blocks copy/paste/right-click/select/print-screen/DevTools shortcuts.
* Blocks navigation to any site that is not Google Forms (ChatGPT, search...).
* After MAX_STRIKES the exam is locked and a best-effort auto-submit is tried.
* Has an EXIT button (asks for the teacher's exit code while an exam is running).
* Writes an exam_log_*.txt file next to the .exe as evidence.

Settings live in config.json (next to the .exe) - no rebuild needed.
"""
import os
import re
import sys
import json
import time
import datetime
import threading
from pathlib import Path

from PyQt5.QtCore import Qt, QTimer, QUrl, QEvent, QObject
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QLineEdit, QStackedWidget,
                             QInputDialog, QMessageBox)
from PyQt5.QtWebEngineWidgets import (QWebEngineView, QWebEnginePage,
                                      QWebEngineProfile, QWebEngineSettings,
                                      QWebEngineScript)

# --------------------------------------------------------------------------
#  CONFIG
# --------------------------------------------------------------------------
APP_DIR = (Path(sys.executable).parent if getattr(sys, "frozen", False)
           else Path(__file__).resolve().parent)

DEFAULTS = {
    "form_url": "https://docs.google.com/forms/d/e/YOUR_FORM_ID/viewform",
    "exit_password": "teacher123",     # needed to quit while exam is running
    "max_strikes": 3,                  # strike N = Final Red Flag
    "duration_minutes": 0,             # 0 = no countdown
    "strike_on_blocked_navigation": True,
    "auto_submit_on_lock": True,
    "clear_clipboard": True,
    "block_screenshots": True,         # Windows 10 2004+: screenshots show black
}


def load_config():
    cfg = dict(DEFAULTS)
    path = APP_DIR / "config.json"
    if path.exists():
        try:
            cfg.update(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            pass
    return cfg


# Only these hosts may be opened. Everything else (ChatGPT, Google Search...) is blocked.
ALLOWED_HOSTS = ("forms.gle", "forms.google.com", "accounts.google.com",
                 "gstatic.com", "googleusercontent.com")


def is_allowed(url: QUrl) -> bool:
    scheme = url.scheme().lower()
    if scheme in ("about", "data", "blob"):
        return True
    if scheme not in ("http", "https"):
        return False
    host, path = url.host().lower(), url.path().lower()
    if host == "docs.google.com":
        return "/forms" in path          # Google Forms only, not Docs/Sheets
    return any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS)


# --------------------------------------------------------------------------
#  WINDOWS-ONLY HELPERS (foreground-window detection, key hook, anti-capture)
# --------------------------------------------------------------------------
IS_WIN = sys.platform == "win32"

if IS_WIN:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int,
                                  wintypes.WPARAM, wintypes.LPARAM)

    class KBDLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                    ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.c_size_t)]

    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
    user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
    user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user32.GetAsyncKeyState.restype = ctypes.c_short
    user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, ctypes.c_void_p, wintypes.DWORD]
    user32.SetWindowsHookExW.restype = ctypes.c_void_p
    user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
    user32.CallNextHookEx.restype = ctypes.c_ssize_t
    user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
    user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD


def foreground_info():
    """(pid, window title) of whatever window currently has the focus."""
    if not IS_WIN:
        return os.getpid(), ""
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return 0, ""
    pid = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    buf = ctypes.create_unicode_buffer(256)
    user32.GetWindowTextW(hwnd, buf, 256)
    return pid.value, buf.value


def protect_from_capture(hwnd: int):
    """Screenshots / screen-share of this window come out black (Win10 2004+)."""
    if not IS_WIN:
        return
    try:
        if not user32.SetWindowDisplayAffinity(hwnd, 0x11):   # WDA_EXCLUDEFROMCAPTURE
            user32.SetWindowDisplayAffinity(hwnd, 0x01)       # WDA_MONITOR fallback
    except Exception:
        pass


class KeyboardLock:
    """Low-level keyboard hook: swallows Win key, Alt+Tab, Alt+Esc, Ctrl+Esc, Alt+F4."""

    def __init__(self):
        self._thread = None
        self._tid = None
        self._proc = None

    def start(self):
        if not IS_WIN or self._thread:
            return
        ready = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(ready,), daemon=True)
        self._thread.start()
        ready.wait(2)

    def stop(self):
        if IS_WIN and self._thread and self._tid:
            user32.PostThreadMessageW(self._tid, 0x0012, 0, 0)   # WM_QUIT
        self._thread, self._tid = None, None

    def _run(self, ready):
        self._tid = kernel32.GetCurrentThreadId()

        def proc(n_code, w_param, l_param):
            if n_code == 0:
                k = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                vk = k.vkCode
                alt = bool(k.flags & 0x20)
                ctrl = bool(user32.GetAsyncKeyState(0x11) & 0x8000)
                if (vk in (0x5B, 0x5C)                      # Win keys
                        or (vk == 0x09 and alt)             # Alt+Tab
                        or (vk == 0x1B and (alt or ctrl))   # Alt+Esc, Ctrl+Esc, Ctrl+Shift+Esc
                        or (vk == 0x73 and alt)):           # Alt+F4
                    return 1
            return user32.CallNextHookEx(None, n_code, w_param, l_param)

        self._proc = HOOKPROC(proc)          # keep a reference or it gets garbage collected
        hook = user32.SetWindowsHookExW(13, self._proc, kernel32.GetModuleHandleW(None), 0)
        ready.set()
        if not hook:
            return
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            pass
        user32.UnhookWindowsHookEx(hook)


# --------------------------------------------------------------------------
#  JAVASCRIPT INJECTED INTO THE FORM PAGE
# --------------------------------------------------------------------------
LOCK_JS = r"""
(function () {
  if (window.__secureExamLoaded) return;
  window.__secureExamLoaded = true;

  // 1) No text selection (stops "select -> search/ask ChatGPT"), but typing in inputs still works
  var css = document.createElement('style');
  css.textContent =
    '*{-webkit-user-select:none!important;user-select:none!important}' +
    'input,textarea,[contenteditable="true"]{-webkit-user-select:text!important;user-select:text!important}';
  document.documentElement.appendChild(css);

  // 2) Block clipboard / context menu / drag&drop
  function stop(e) { e.preventDefault(); e.stopImmediatePropagation(); return false; }
  ['copy', 'cut', 'paste', 'contextmenu', 'dragstart', 'drop'].forEach(function (t) {
    window.addEventListener(t, stop, true);
  });

  // 3) Block shortcuts: Ctrl/Cmd + C V X P S U, DevTools (F12, Ctrl+Shift+I/J/C), PrintScreen
  window.addEventListener('keydown', function (e) {
    var k = (e.key || '').toLowerCase(), c = e.ctrlKey || e.metaKey;
    if (e.key === 'F12' || e.key === 'PrintScreen' ||
        (c && ['c', 'v', 'x', 'p', 's', 'u'].indexOf(k) > -1) ||
        (c && e.shiftKey && ['i', 'j', 'c'].indexOf(k) > -1) ||
        (e.shiftKey && e.key === 'Insert') || (c && e.key === 'Insert')) { stop(e); }
  }, true);
  window.addEventListener('keyup', function (e) {
    if (e.key === 'PrintScreen') { try { navigator.clipboard.writeText(''); } catch (x) {} }
  }, true);

  // 4) Page Visibility / blur listeners -> reported to Python (logged as extra evidence;
  //    the strike itself is counted by the native focus watcher so nothing is counted twice)
  function sig(t) { console.log('__SX__:' + t); }
  document.addEventListener('visibilitychange', function () { if (document.hidden) sig('visibilitychange-hidden'); });
  window.addEventListener('blur', function () { sig('window-blur'); });
})();
"""

SUBMIT_JS = r"""
(function () {
  var re = /^(submit|send|isumite|enviar|envoyer|senden|invia|提交|送信|제출)$/i;
  var b = [].slice.call(document.querySelectorAll('div[role="button"],button'));
  for (var i = 0; i < b.length; i++) {
    if (re.test((b[i].innerText || '').trim())) { b[i].click(); return 'submit-clicked'; }
  }
  return 'no-submit-button-on-current-page';
})()
"""

WARNING_TEXT = ("Prohibited Action Detected! Opening other applications, tabs, notes, "
                "Word files, PDFs, or ChatGPT is strictly forbidden.")


# --------------------------------------------------------------------------
#  WEB PAGE THAT REFUSES TO LEAVE GOOGLE FORMS
# --------------------------------------------------------------------------
class GuardedPage(QWebEnginePage):
    def __init__(self, profile, parent, on_blocked, on_signal):
        super().__init__(profile, parent)
        self._on_blocked = on_blocked
        self._on_signal = on_signal

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        if is_main_frame and not is_allowed(url):
            self._on_blocked(url.toString())
            return False
        return True

    def createWindow(self, window_type):          # target=_blank / window.open
        self._on_blocked("(new window or tab)")
        return None

    def javaScriptConsoleMessage(self, level, message, line, source):
        if message.startswith("__SX__:"):
            self._on_signal(message[7:])


# --------------------------------------------------------------------------
#  QT-LEVEL KEY FILTER (second layer behind the JavaScript one)
# --------------------------------------------------------------------------
class KeyGuard(QObject):
    def __init__(self, on_blocked):
        super().__init__()
        self.on_blocked = on_blocked

    def eventFilter(self, obj, ev):
        t = ev.type()
        if t in (QEvent.KeyPress, QEvent.KeyRelease):
            key, mods = ev.key(), ev.modifiers()
            ctrl = bool(mods & Qt.ControlModifier)
            shift = bool(mods & Qt.ShiftModifier)
            bad = key == Qt.Key_Print
            if t == QEvent.KeyPress:
                if key == Qt.Key_F12:
                    bad = True
                elif ctrl and key in (Qt.Key_C, Qt.Key_V, Qt.Key_X, Qt.Key_P,
                                      Qt.Key_S, Qt.Key_U, Qt.Key_Insert):
                    bad = True
                elif ctrl and shift and key in (Qt.Key_I, Qt.Key_J, Qt.Key_C):
                    bad = True
                elif shift and key == Qt.Key_Insert:
                    bad = True
            if bad:
                self.on_blocked(key)
                return True
        return False


# --------------------------------------------------------------------------
#  UI
# --------------------------------------------------------------------------
STYLE = """
QWidget{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',Arial;font-size:14px;}
#bar{background:#020617;border-bottom:1px solid #1e293b;}
#h1{font-size:30px;font-weight:700;}
#sub{color:#94a3b8;}
QLineEdit{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px;font-size:15px;}
QPushButton{background:#2563eb;color:white;border:none;border-radius:8px;padding:11px 24px;font-weight:600;font-size:15px;}
QPushButton:hover{background:#1d4ed8;}
#exit{background:#475569;padding:6px 18px;font-size:13px;}
#exit:hover{background:#dc2626;}
#err{color:#f87171;}
"""


class ExamWindow(QWidget):
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.max_strikes = max(1, int(cfg["max_strikes"]))
        self.strikes = 0
        self.state = "idle"            # idle -> running -> locked | submitted
        self.allow_close = False
        self.student = self.student_id = ""
        self.log_file = None
        self.incidents = []
        self.deadline = None
        self.away_ticks = 0
        self._lost_flag = False
        self._n = 0
        self.kb = KeyboardLock()

        self.setWindowTitle("SecureExam")
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setStyleSheet(STYLE)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_toolbar())
        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)
        self.stack.addWidget(self._build_start_page())   # 0
        self.stack.addWidget(self._build_exam_page())    # 1
        self.stack.addWidget(self._build_alert_page())   # 2

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(250)
        QApplication.instance().applicationStateChanged.connect(self.on_app_state)

    # ---------------- UI builders ----------------
    def _build_toolbar(self):
        bar = QWidget()
        bar.setObjectName("bar")
        bar.setFixedHeight(46)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 0)
        self.lbl_student = QLabel("🔒 SecureExam")
        self.lbl_timer = QLabel("")
        self.lbl_strikes = QLabel("")
        self.btn_exit = QPushButton("Exit")
        self.btn_exit.setObjectName("exit")
        self.btn_exit.setCursor(Qt.PointingHandCursor)
        self.btn_exit.clicked.connect(self.request_exit)
        lay.addWidget(self.lbl_student)
        lay.addStretch(1)
        lay.addWidget(self.lbl_timer)
        lay.addSpacing(20)
        lay.addWidget(self.lbl_strikes)
        lay.addSpacing(20)
        lay.addWidget(self.btn_exit)
        return bar

    def _build_start_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setAlignment(Qt.AlignCenter)
        box = QWidget()
        box.setFixedWidth(560)
        lay = QVBoxLayout(box)
        lay.setSpacing(12)

        t = QLabel("🔒 Secure Exam Browser")
        t.setObjectName("h1")
        t.setAlignment(Qt.AlignCenter)
        lay.addWidget(t)

        rules = QLabel(
            "<b>Read before you start:</b><ul>"
            "<li>The exam runs in <b>fullscreen</b>. Do not switch windows, tabs or apps.</li>"
            "<li>Copy, paste, right-click, screenshots and DevTools are disabled.</li>"
            "<li>Opening Word, PDFs, notes, ChatGPT or any other website is <b>forbidden</b>.</li>"
            f"<li>Every violation is a strike. <b>Strike {self.max_strikes} = Final Red Flag</b>: "
            "the exam is locked and submitted automatically.</li>"
            "<li>Everything is logged for your teacher.</li></ul>")
        rules.setWordWrap(True)
        rules.setTextFormat(Qt.RichText)
        lay.addWidget(rules)

        self.in_name = QLineEdit()
        self.in_name.setPlaceholderText("Full name")
        self.in_id = QLineEdit()
        self.in_id.setPlaceholderText("Student ID")
        lay.addWidget(self.in_name)
        lay.addWidget(self.in_id)

        self.lbl_err = QLabel("")
        self.lbl_err.setObjectName("err")
        self.lbl_err.setWordWrap(True)
        lay.addWidget(self.lbl_err)

        btn = QPushButton("Start Exam (Fullscreen)")
        btn.clicked.connect(self.start_exam)
        lay.addWidget(btn)
        outer.addWidget(box)
        return page

    def _build_exam_page(self):
        self.profile = QWebEngineProfile(self)           # off-the-record: nothing saved to disk
        ua = re.sub(r"\s?QtWebEngine/[\d.]+", "", self.profile.httpUserAgent())
        self.profile.setHttpUserAgent(ua)
        self.web = QWebEngineView()
        self.page = GuardedPage(self.profile, self.web, self.on_blocked_nav, self.on_js_signal)
        self.web.setPage(self.page)
        self.web.setContextMenuPolicy(Qt.NoContextMenu)  # no right-click menu / lookups
        st = self.page.settings()
        st.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, False)
        st.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, False)
        st.setAttribute(QWebEngineSettings.JavascriptCanPaste, False)
        st.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        st.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, False)

        script = QWebEngineScript()
        script.setName("secure-exam-lock")
        script.setSourceCode(LOCK_JS)
        script.setInjectionPoint(QWebEngineScript.DocumentReady)
        script.setWorldId(QWebEngineScript.MainWorld)
        script.setRunsOnSubFrames(True)
        self.page.scripts().insert(script)

        self.web.urlChanged.connect(self.on_url_changed)
        return self.web

    def _build_alert_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setAlignment(Qt.AlignCenter)
        box = QWidget()
        box.setFixedWidth(760)
        lay = QVBoxLayout(box)
        lay.setSpacing(16)
        self.a_title = QLabel()
        self.a_title.setStyleSheet("font-size:38px;font-weight:800;")
        self.a_msg = QLabel()
        self.a_msg.setStyleSheet("font-size:20px;")
        self.a_detail = QLabel()
        self.a_detail.setStyleSheet("color:#94a3b8;font-size:15px;")
        for w in (self.a_title, self.a_msg, self.a_detail):
            w.setWordWrap(True)
            w.setAlignment(Qt.AlignCenter)
            w.setTextFormat(Qt.PlainText)
            lay.addWidget(w)
        self.btn_continue = QPushButton("I understand - return to exam")
        self.btn_continue.clicked.connect(self.resume_exam)
        lay.addWidget(self.btn_continue, alignment=Qt.AlignCenter)
        outer.addWidget(box)
        return page

    # ---------------- helpers ----------------
    def log(self, msg):
        if not self.log_file:
            return
        line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n"
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass

    def update_labels(self):
        self.lbl_strikes.setText(f"Strikes: {self.strikes}/{self.max_strikes}"
                                 if self.state != "idle" else "")
        color = "#f87171" if self.strikes else "#e2e8f0"
        self.lbl_strikes.setStyleSheet(f"color:{color};font-weight:600;")

    def _show_alert_page(self, title, msg, detail, color, can_continue):
        self.a_title.setText(title)
        self.a_title.setStyleSheet(f"font-size:38px;font-weight:800;color:{color};")
        self.a_msg.setText(msg)
        self.a_detail.setText(detail)
        self.btn_continue.setVisible(can_continue)
        self.stack.setCurrentIndex(2)
        self.activateWindow()
        self.raise_()

    # ---------------- start / resume ----------------
    def start_exam(self):
        name, sid = self.in_name.text().strip(), self.in_id.text().strip()
        url = QUrl(self.cfg["form_url"])
        if "YOUR_FORM_ID" in self.cfg["form_url"]:
            self.lbl_err.setText("Teacher: set \"form_url\" in config.json first.")
            return
        if not is_allowed(url):
            self.lbl_err.setText("form_url must be a Google Forms link.")
            return
        if not name or not sid:
            self.lbl_err.setText("Please enter your name and student ID.")
            return

        if not self.isFullScreen():          # force fullscreen before starting
            self.showFullScreen()
        self.student, self.student_id = name, sid
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w\-]+", "_", name)[:30]
        self.log_file = APP_DIR / f"exam_log_{safe}_{stamp}.txt"
        try:
            self.log_file.touch()
        except OSError:
            self.log_file = Path.home() / self.log_file.name
        self.log(f"EXAM START | {name} | ID {sid} | form {self.cfg['form_url']}")

        self.strikes, self.incidents = 0, []
        self.state = "running"
        mins = int(self.cfg.get("duration_minutes", 0) or 0)
        self.deadline = time.time() + mins * 60 if mins else None
        self.lbl_student.setText(f"🔒 {name}  |  ID {sid}")
        self.update_labels()
        self.web.load(url)
        self.stack.setCurrentIndex(1)
        self.web.setFocus()
        self.kb.start()

    def resume_exam(self):
        if self.state == "running":
            self.stack.setCurrentIndex(1)
            self.web.setFocus()

    # ---------------- detection ----------------
    def tick(self):
        if self.state != "running":
            return
        self._n += 1
        if self.cfg.get("clear_clipboard", True) and self._n % 2 == 0:
            QApplication.clipboard().clear()          # nothing can be pasted in from outside
        if not self.isFullScreen():
            self.showFullScreen()

        if self.deadline:
            left = int(self.deadline - time.time())
            if left <= 0:
                self.terminate("Time limit reached.", red_flag=False)
                return
            self.lbl_timer.setText(f"⏱ {left // 60:02d}:{left % 60:02d}")

        if IS_WIN:                                    # another app has the focus?
            pid, title = foreground_info()
            if pid != os.getpid():
                self.away_ticks += 1
                if self.away_ticks == 2:              # ~0.5s debounce, one strike per episode
                    self.register_violation(
                        f"Focus left the exam -> {title or 'another application / desktop'}")
            else:
                self.away_ticks = 0

    def on_app_state(self, state):                    # non-Windows fallback
        if IS_WIN or self.state != "running":
            return
        if state != Qt.ApplicationActive:
            if not self._lost_flag:
                self._lost_flag = True
                self.register_violation("Exam window lost focus (other app / window)")
        else:
            self._lost_flag = False

    def on_blocked_nav(self, url):
        self.log(f"BLOCKED NAVIGATION -> {url}")
        if self.state == "running" and self.cfg.get("strike_on_blocked_navigation", True):
            self.register_violation(f"Tried to open a blocked site: {url}")

    def on_js_signal(self, kind):
        if self.state == "running":
            self.log(f"(page event) {kind}")

    def on_key_blocked(self, key):
        QApplication.clipboard().clear()
        if self.state == "running":
            self.log(f"Blocked shortcut (key code {key})")

    def on_url_changed(self, url):
        if "/formresponse" not in url.path().lower():
            return
        if self.state == "running":                   # student submitted normally
            self.state = "submitted"
            self.deadline = None
            self.kb.stop()
            self.lbl_timer.setText("✔ Submitted - you may exit")
            self.log("FORM SUBMITTED by student")
        elif self.state == "locked":
            self.log("Form response received after lock (auto-submit worked)")

    # ---------------- strikes ----------------
    def register_violation(self, reason):
        if self.state != "running":
            return
        self.strikes += 1
        self.incidents.append(reason)
        self.log(f"VIOLATION {self.strikes}/{self.max_strikes}: {reason}")
        self.update_labels()
        if self.strikes >= self.max_strikes:
            self.terminate(f"Final Red Flag. Last violation: {reason}")
            return
        last = self.strikes == self.max_strikes - 1
        extra = ("This is your LAST warning. The next violation locks and submits your exam."
                 if last else
                 f"Warning {self.strikes} of {self.max_strikes - 1}. "
                 f"At strike {self.max_strikes} your exam is locked and submitted.")
        self._show_alert_page(f"⚠ WARNING {self.strikes}", WARNING_TEXT,
                              f"Detected: {reason}\n{extra}",
                              "#f59e0b" if not last else "#f97316", True)

    def terminate(self, reason, red_flag=True):
        if self.state != "running":
            return
        self.state = "locked"
        self.log(f"EXAM LOCKED: {reason}")
        self.lbl_timer.setText("🔒 LOCKED")
        self._show_alert_page("🚩 FINAL RED FLAG" if red_flag else "⏰ TIME IS UP",
                              "Your exam is being locked and submitted automatically...",
                              reason, "#ef4444", False)
        if self.cfg.get("auto_submit_on_lock", True):
            self.page.runJavaScript(SUBMIT_JS, lambda r: self.log(f"Auto-submit attempt: {r}"))
        QTimer.singleShot(3500, self._finish_lock)

    def _finish_lock(self):
        self.web.setUrl(QUrl("about:blank"))          # nothing left to answer
        incidents = "\n".join(f"{i + 1}. {s}" for i, s in enumerate(self.incidents)) or "-"
        self._show_alert_page(
            "🔒 EXAM LOCKED",
            "Please raise your hand and inform your teacher.",
            f"Student: {self.student} ({self.student_id})\nIncidents:\n{incidents}\n\n"
            f"Log file: {self.log_file}",
            "#ef4444", False)

    # ---------------- exit ----------------
    def request_exit(self):
        if self.state in ("idle", "submitted"):
            self._quit()
            return
        pwd, ok = QInputDialog.getText(self, "Exit exam",
                                       "Enter the exit code given by your teacher:",
                                       QLineEdit.Password)
        if not ok:
            return
        if pwd == str(self.cfg["exit_password"]):
            self.log("EXIT with teacher exit code")
            self._quit()
        else:
            self.log("Wrong exit code entered")
            QMessageBox.warning(self, "Exit", "Incorrect exit code.")

    def _quit(self):
        self.allow_close = True
        self.kb.stop()
        QApplication.quit()

    def closeEvent(self, ev):                          # Alt+F4 / taskbar close is ignored
        if self.allow_close:
            ev.accept()
        else:
            ev.ignore()


def main():
    os.environ.pop("QTWEBENGINE_REMOTE_DEBUGGING", None)      # keep DevTools off
    QApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
    app = QApplication(sys.argv)
    cfg = load_config()
    win = ExamWindow(cfg)
    guard = KeyGuard(win.on_key_blocked)
    app.installEventFilter(guard)
    win.showFullScreen()
    if cfg.get("block_screenshots", True):
        protect_from_capture(int(win.winId()))
    rc = app.exec_()
    os._exit(rc)


if __name__ == "__main__":
    main()
