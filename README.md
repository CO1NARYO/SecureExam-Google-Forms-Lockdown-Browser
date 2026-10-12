# SecureExam – Google Forms Lockdown Browser (Python + PyQt5)

A fullscreen exam browser that opens **one** Google Form, watches for cheating behaviour,
and locks the exam after too many violations. Ships as a single `SecureExam.exe` with an **Exit** button.
No server, no dashboard – each student's PC writes its own log file.

## 1. Recommended tech stack (and why)

| Option | Can detect other apps (Word, PDF, ChatGPT app)? | Can block Alt+Tab / Win key? | Verdict |
|---|---|---|---|
| Web page + Page Visibility API only | Only tab/window blur, easy to bypass | No | Too weak alone |
| Chrome extension | Tabs only, no desktop apps | No | Weak, student can disable it |
| Electron kiosk | Yes | Yes (native module) | Good, but 150 MB+ and needs Node |
| **Python + PyQt5 WebEngine + Win32 (ctypes)** ← chosen | **Yes** (foreground-window watcher) | **Yes** (low-level key hook) | Simple, one .exe, easy to edit |

## 2. Architecture

```
 config.json ──► SecureExam.exe
                  ├─ Start screen (name + ID, rules)  → forces fullscreen
                  ├─ QWebEngineView  → Google Form (only docs.google.com/forms, forms.gle, Google login allowed)
                  │     └─ injected JS: no select, no copy/paste/right-click, no F12/Ctrl+Shift+I,
                  │                      blur + visibilitychange listeners
                  ├─ Focus watcher (250 ms): is the foreground window ours? Which app took it?
                  ├─ Keyboard hook: Win key, Alt+Tab, Alt+Esc, Ctrl+Esc, Alt+F4 swallowed
                  ├─ Strike engine: Warning 1 → Warning 2 → Final Red Flag → lock + auto-submit try
                  └─ exam_log_<name>_<time>.txt  (evidence for the teacher)
```

Where the listeners live: `LOCK_JS` (contextmenu, copy, cut, paste, keydown, blur, visibilitychange),
`KeyGuard` (Qt-level keydown filter), `tick()` (native focus watcher), `KeyboardLock` (Windows key hook).

## 3. Step-by-step: prepare, build, deploy

### A. Prepare the Google Form
1. Settings → Responses: **turn OFF "Limit to 1 response" and "Require sign-in"** (Google blocks sign-in inside embedded browsers). Instead add two required questions: *Full name* and *Student ID*.
2. Get the link: Send → link icon → copy (`https://docs.google.com/forms/d/e/…/viewform` or `forms.gle/…`).
3. Optional: Settings → Presentation → shuffle question order; put "Time limit" in `duration_minutes`.

### B. Configure
Edit `config.json`:
```json
{ "form_url": "PASTE YOUR LINK", "exit_password": "your-secret", "max_strikes": 3, "duration_minutes": 45 }
```

### C. Test from source (Windows 10/11, Python 3.9+)
```
pip install -r requirements.txt
python secure_exam.py
```

### D. Build the .exe
Double-click **build_exe.bat** → result in `dist\` (`SecureExam.exe` + `config.json`).
If antivirus complains about `--onefile`, build with `--onedir` instead.

### E. Distribute
1. Give students the `dist` folder (USB / school drive / LMS). Share the **exit code** only after the exam, or privately in emergencies.
2. Students run `SecureExam.exe`, enter name + ID, click **Start**.
3. Collect `exam_log_*.txt` from each PC (or have the student send it) and compare with the Google Form responses (matching name/ID/timestamp).

## 4. Pre-exam test checklist
- Alt+Tab, Win key, Ctrl+Esc do nothing
- Clicking the taskbar / opening Notepad → Warning 1 appears with the required message
- 3rd violation → "Final Red Flag", form submit attempt, locked screen
- Copy/paste/right-click/F12 blocked; typing answers still works
- Opening a link to Google/ChatGPT is blocked and counted
- Exit button asks for the exit code; correct code closes the app

## 5. Honest limitations (read this)
- **Ctrl+Alt+Del / Task Manager from the lock screen cannot be blocked by any normal app.** Killing the process stops the exam – the log will simply end without "FORM SUBMITTED". Treat a missing log as suspicious.
- **Auto-submit is best-effort.** It clicks the form's *Submit* button if it is on the current page. On multi-section forms or with unanswered required questions Google will refuse. The lock itself always works.
- A phone, a second PC, a second monitor or a virtual machine cannot be detected by software on the exam PC. Use in-room supervision for high-stakes exams.
- Linux/macOS: the app runs, focus detection uses Qt's application-state event, but the key hook, screenshot-block and foreground-window title are Windows-only.
- "Block screenshots" blanks screenshots/screen-sharing of the exam window (Windows 10 2004+). Disable it in `config.json` if you need to record the screen.
- The app clears the clipboard every ~0.5 s during the exam (so pre-copied ChatGPT text cannot be pasted). Students lose clipboard contents while it runs.
