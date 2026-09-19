@echo off
"C:\Program Files\GitHub CLI\gh.exe" auth login --web --hostname github.com --git-protocol https -h github.com > "%~dp0glogin.log" 2>&1
