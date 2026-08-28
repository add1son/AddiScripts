;==================================================================
; Markdown Helper
; AutoHotkey v2.0 script that adds hotkeys for fast Markdown editing
; License: see LICENSE
;==================================================================
;
; HOTKEYS
;
; |-------------+----------------------------+----------------+-----------------------------------|
; | Hotkey       | Action                     | Markdown        | HTML                              |
; |-------------+----------------------------+----------------+-----------------------------------|
; | Alt+I        | Emphasis (wraps selection) | *text*          | <em>text</em>                      |
; | Alt+B        | Bold (wraps selection)     | **text**        | <strong>text</strong>              |
; | Alt+C        | Inline code (wraps sel.)   | `code`          | <code>code</code>                  |
; | Alt+S        | Strikethrough (wraps sel.) | ~~text~~        | <del>text</del>                    |
; | Alt+Q        | Blockquote                 | > text          | <blockquote>text</blockquote>      |
; | Alt+N        | Hard line break            | text␣␣\n        | <br />                             |
; | Alt+.        | Unordered list item        | * item          | <ul><li>item</li></ul>             |
; | Alt+,        | Ordered list item          | 1. item         | <ol><li>item</li></ol>             |
; | Alt+Shift+.  | Task list item             | - [ ] item      | <input type="checkbox">            |
; | Alt+T        | Indent (4 spaces)          | ____            | -                                   |
; | Alt+L        | Link wizard                | [text](url)     | <a href="url">text</a>             |
; | Alt+P        | Image wizard               | ![alt](url)     | <img src="url" alt="alt" />        |
; | Alt+-        | Horizontal rule            | ---             | <hr />                              |
; | Alt+Shift+T  | Table skeleton             | \| a \| b \|    | <table>...</table>                 |
; | Ctrl+Alt+1-6 | Heading level 1-6          | # ... ######    | <h1>...</h6>                       |
; | Alt+#        | HTML code-block beautifier | -               | -                                   |
; |-------------+----------------------------+----------------+-----------------------------------|
;
; Wrapping hotkeys (I, B, C, S) work two ways:
;   - Text selected  -> selection gets wrapped in place
;   - No selection    -> markers are inserted with the cursor left between them
;
;==================================================================
; GENERAL SETTINGS
;==================================================================
#Requires AutoHotkey v2.0
#SingleInstance Force
SendMode "Input"
SetWorkingDir A_ScriptDir
SetTitleMatchMode 2

;==================================================================
; HELPER FUNCTIONS
;==================================================================

; Returns the currently selected text without permanently touching
; the clipboard contents the user already had.
GetSelectedText() {
    savedClip := ClipboardAll()
    A_Clipboard := ""
    Send("^c")
    if !ClipWait(0.4)
        return ""
    selected := A_Clipboard
    A_Clipboard := savedClip
    return selected
}

; Wraps the current selection in startTag/endTag.
; If nothing is selected, inserts an empty pair and places the
; cursor between the tags so the user can start typing immediately.
WrapSelection(startTag, endTag) {
    selected := GetSelectedText()
    if (selected != "") {
        SendInput(startTag . selected . endTag)
    } else {
        SendInput(startTag . endTag)
        Loop StrLen(endTag)
            Send("{Left}")
    }
}

; Inserts a Markdown heading of the given level at the start of a
; new line.
InsertHeading(level) {
    Send("{Enter}")
    Loop level
        Send("#")
    Send("{Space}")
}

;==================================================================
; TEXT FORMATTING HOTKEYS
;==================================================================

; *text* -> <em>text</em>
!i::WrapSelection("*", "*")

; **text** -> <strong>text</strong>
!b::WrapSelection("**", "**")

; `code` -> <code>code</code>
!c::WrapSelection("``", "``")

; ~~text~~ -> <del>text</del>
!s::WrapSelection("~~", "~~")

; > text -> <blockquote>text</blockquote>
!q:: {
    Send("{Enter}")
    Send(">")
    Send("{Space}")
}

; Two trailing spaces + newline = hard line break
!n::Send("{Space 2}{Enter}")

;==================================================================
; LISTS
;==================================================================

; * item -> <ul><li>item</li></ul>
!.:: {
    Send("{Enter}{Enter}")
    Send("*")
    Send("{Space}")
}

; 1. item -> <ol><li>item</li></ol>
!,:: {
    Send("{Enter}{Enter}")
    Send("1.")
    Send("{Space}")
}

; - [ ] item -> unchecked task list entry
!+.:: {
    Send("{Enter}{Enter}")
    Send("-")
    Send("{Space}")
    Send("[")
    Send("{Space}")
    Send("]")
    Send("{Space}")
}

; 4-space indent, matches Markdown's nested-list indent width
!t::Send("{Space 4}")

;==================================================================
; HEADINGS (Ctrl+Alt+1 .. Ctrl+Alt+6)
;==================================================================
^!1::InsertHeading(1)
^!2::InsertHeading(2)
^!3::InsertHeading(3)
^!4::InsertHeading(4)
^!5::InsertHeading(5)
^!6::InsertHeading(6)

;==================================================================
; HORIZONTAL RULE
;==================================================================
!-:: {
    Send("{Enter}{Enter}")
    Send("---")
    Send("{Enter}{Enter}")
}

;==================================================================
; TABLE SKELETON
;==================================================================
; Alt+Shift+T inserts a basic 2-column table. Edit the headers and
; cell text after it's placed, add pipes for more columns.
!+t:: {
    template := "| Header 1 | Header 2 |`n| -------- | -------- |`n| Cell 1   | Cell 2   |`n"
    SendInput(template)
}

;==================================================================
; LINK WIZARD (Alt+L)
;==================================================================
!l::ShowLinkWizard()

ShowLinkWizard(*) {
    linkText := GetSelectedText()

    linkGui := Gui(, "Insert Link")
    linkGui.Add("Text", , "Text to display:")
    edtText := linkGui.Add("Edit", "w300", linkText)
    linkGui.Add("Text", , "URL:")
    edtUrl := linkGui.Add("Edit", "w300", "http://")
    btnOK := linkGui.Add("Button", "default w80", "&OK")
    btnCancel := linkGui.Add("Button", "x+10 w80", "&Cancel")

    btnOK.OnEvent("Click", InsertAndClose)
    btnCancel.OnEvent("Click", (*) => linkGui.Destroy())
    linkGui.OnEvent("Close", (*) => linkGui.Destroy())
    linkGui.OnEvent("Escape", (*) => linkGui.Destroy())

    InsertAndClose(*) {
        SendInput("[" . edtText.Value . "](" . edtUrl.Value . ")")
        linkGui.Destroy()
    }

    linkGui.Show()
}

;==================================================================
; IMAGE WIZARD (Alt+P)
;==================================================================
!p::ShowImageWizard()

ShowImageWizard(*) {
    imgGui := Gui(, "Insert Image")
    imgGui.Add("Text", , "Image URL:")
    edtUrl := imgGui.Add("Edit", "w300")
    imgGui.Add("Text", , "Alt text:")
    edtAlt := imgGui.Add("Edit", "w300")
    btnPreview := imgGui.Add("Button", "default w80", "&Preview")
    btnInsert := imgGui.Add("Button", "x+10 w80", "&Insert")
    btnCancel := imgGui.Add("Button", "x+10 w80", "&Cancel")

    btnPreview.OnEvent("Click", ShowPreview)
    btnInsert.OnEvent("Click", InsertAndClose)
    btnCancel.OnEvent("Click", (*) => imgGui.Destroy())
    imgGui.OnEvent("Close", (*) => imgGui.Destroy())
    imgGui.OnEvent("Escape", (*) => imgGui.Destroy())

    ShowPreview(*) {
        if (edtUrl.Value = "") {
            MsgBox("Enter a URL first.", , "Icon!")
            return
        }
        tempFile := A_Temp . "\markdown_ahk_preview.tmp"
        try {
            Download(edtUrl.Value, tempFile)
        } catch as err {
            MsgBox("Could not download image:`n" . err.Message, , "Icon!")
            return
        }
        previewGui := Gui(, "Preview")
        previewGui.Add("Picture", "w300 h300", tempFile)
        btnClose := previewGui.Add("Button", "default", "&Close")
        btnClose.OnEvent("Click", (*) => previewGui.Destroy())
        previewGui.OnEvent("Close", (*) => previewGui.Destroy())
        previewGui.OnEvent("Escape", (*) => previewGui.Destroy())
        previewGui.Show()
    }

    InsertAndClose(*) {
        SendInput("![" . edtAlt.Value . "](" . edtUrl.Value . ")")
        imgGui.Destroy()
    }

    imgGui.Show()
}

;==================================================================
; HTML CODE-BLOCK BEAUTIFIER (Alt+#)
;==================================================================
; Picks an HTML file (e.g. rendered from Markdown), finds any
; <code>...</code> sections and, within those sections only:
;   - replaces tabs with 4 spaces
;   - replaces spaces with &nbsp;
;   - appends <br /> to the end of every line
; Writes the result to <name>_converted.html next to the source.
!#::RunCodeBeautifier()

RunCodeBeautifier(*) {
    sourceFile := FileSelect(3, , "Pick an HTML file to convert.", "HTML Files (*.html; *.htm)")
    if (sourceFile = "")
        return

    SplitPath(sourceFile, , &sourceDir, , &sourceNameNoExt)
    destFile := sourceDir . "\" . sourceNameNoExt . "_converted.html"

    if FileExist(destFile) {
        result := MsgBox("Overwrite the existing file?`n`n" . destFile, "Confirm", "YesNo 48")
        if (result = "Yes")
            FileDelete(destFile)
        else
            return
    }

    ConvertHtmlCodeBlocks(sourceFile, destFile)
    MsgBox("Done. Saved to:`n" . destFile, , "Iconi")
}

; Reads sourceFile line by line, transforms lines inside <code>
; sections, writes everything to destFile.
ConvertHtmlCodeBlocks(sourceFile, destFile) {
    inCodeSection := false
    Loop Read, sourceFile, destFile {
        line := A_LoopReadLine

        if InStr(line, "<code>")
            inCodeSection := true

        if (inCodeSection) {
            line := StrReplace(line, "`t", "    ")
            line := StrReplace(line, " ", "&nbsp;")
            FileAppend(line . " <br />`n")
        } else {
            FileAppend(line . "`n")
        }

        if InStr(line, "</code>")
            inCodeSection := false
    }
}
