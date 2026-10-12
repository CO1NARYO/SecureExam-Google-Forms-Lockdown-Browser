@echo off
echo === Installing dependencies ===
python -m pip install -r requirements.txt
echo === Building SecureExam.exe ===
python -m PyInstaller --noconfirm --clean --onefile --windowed --name SecureExam secure_exam.py
copy /Y config.json dist\config.json
echo.
echo Done. Give students the whole "dist" folder (SecureExam.exe + config.json).
pause
