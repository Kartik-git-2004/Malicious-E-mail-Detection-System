@echo off
echo Opening Malicious Email Detection System Web Interface...

REM Create web directory if it doesn't exist
if not exist web mkdir web

REM Launch the web interface
start "" "web/index.html"

echo Web interface opened in your default browser.
pause 