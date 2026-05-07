#Requires AutoHotkey v2.0

; Using F10 as the mute/unmute key for Teams regardless of if Teams is focused or not, Define as you wish
F10::
{
    SetTitleMatchMode(2)
    
    if WinExist("Microsoft Teams")
    {
        originalWin := WinGetID("A")
        
        ; Force focus on Teams
        WinActivate("Microsoft Teams")
        
        ; Wait up to 1 second for Teams to become the active window
        if WinWaitActive("Microsoft Teams", , 1)
        {
            ; extra small sleep helps WebView2
            Sleep(100) 
            
            ; Send the keys with a longer press duration
            SetKeyDelay(50, 50)
            SendEvent("^+m") 
            
            ; Wait a moment before jumping back so Teams doesn't lose the command
            Sleep(100)
            
            ; Return to your original app
            WinActivate("ahk_id " originalWin)
            
            ToolTip("Teams Toggled")
            SetTimer () => ToolTip(), -1000
        }
    }
}
