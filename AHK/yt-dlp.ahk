#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
; #Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.
F14:: ; This is what I have the left most footpedal mapped to, intended use is to activate switch / key when it is present in the clipboard. The script then runs command prompt, changes directory to yt-dlp.exe and then pastes the clipboard input 

Run, cmd.exe
sleep, 500
;Send /your/path/to/yt-dlp.exe directory
Send yt-dlp.exe{SPACE}
SendInput %Clipboard%{Enter}
return