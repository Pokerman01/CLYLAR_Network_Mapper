@echo off
rem Starts the local Whisper program for voice commands (whisper_worker.py; setup guide: docs/whisper-setup.md).
rem Leave this window open while you use voice commands. Close it to stop Whisper (the chat microphone then uses the browser's own engine).
rem It needs the voice-lab folder with its own Python environment and the models. If you moved it, set CLYLAR_WHISPER_HOME to its path first.
setlocal
set "LAB=%USERPROFILE%\Desktop\clylar-whisper-lab"
if not "%CLYLAR_WHISPER_HOME%"=="" set "LAB=%CLYLAR_WHISPER_HOME%"
if not exist "%LAB%\venv\Scripts\python.exe" (
  echo Cannot find %LAB%\venv\Scripts\python.exe
  echo Put the voice-lab folder there or set CLYLAR_WHISPER_HOME to its path.
  pause
  exit /b 1
)
echo Starting local Whisper (model loads in about 10 seconds)...
"%LAB%\venv\Scripts\python.exe" "%~dp0whisper_worker.py" --model "%LAB%\models\thai-large" --instance "%~dp0instance"
echo.
echo Whisper stopped.
pause
