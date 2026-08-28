# AutoHotkey Scripts

Welcome to the AutoHotkeyScripts folder! This directory contains a collection of AutoHotkey scripts designed to automate tasks and enhance productivity on your Windows system.

## Scripts
1. [TeamsMutify.ahk](TeamsMutify.ahk)

- **Description:** Push to mute / unmute in Microsoft Teams regardless of if the window is focused
- **Activation:** F10

2. [clipboard_as_keyboard.ahk](clipboard_as_keyboard.ahk)

- **Description**: Pastes current clipboard output as keyboard output
- **Activation:**: Ctrl + Shift + Z

3. [yt-dlp.ahk](yt-dlp.ahk)

- **Description**: yt-dlp hook to integrate into foot pedal
- **Activation:**: F14

4. [markdown.ahk](markdown.ahk)
- **Description**: optimize markdown formatting via global hotkeys, inspired by [this](https://github.com/koepalex/autohotkey-markdown/blob/master/markdown.ahk)
- **Activation**: Many,

| Hotkey | Action | Markdown | HTML |
|---|---|---|---|
| Alt+I | Emphasis (wraps selection) | `*text*` | `<em>text</em>` |
| Alt+B | Bold (wraps selection) | `**text**` | `<strong>text</strong>` |
| Alt+C | Inline code (wraps selection) | `` `code` `` | `<code>code</code>` |
| Alt+S | Strikethrough (wraps selection) | `~~text~~` | `<del>text</del>` |
| Alt+Q | Blockquote | `> text` | `<blockquote>text</blockquote>` |
| Alt+N | Hard line break | two trailing spaces + newline | `<br />` |
| Alt+. | Unordered list item | `* item` | `<ul><li>item</li></ul>` |
| Alt+, | Ordered list item | `1. item` | `<ol><li>item</li></ol>` |
| Alt+Shift+. | Task list item | `- [ ] item` | checkbox input |
| Alt+T | Indent (4 spaces) | â€” | â€” |
| Alt+L | Link wizard | `[text](url)` | `<a href="url">text</a>` |
| Alt+P | Image wizard | `![alt](url)` | `<img src="url" alt="alt" />` |
| Alt+- | Horizontal rule | `---` | `<hr />` |
| Alt+Shift+T | Table skeleton | `\| a \| b \|` | `<table>...</table>` |
| Ctrl+Alt+1 â€“ Ctrl+Alt+6 | Heading level 1â€“6 | `#` through `######` | `<h1>` â€“ `<h6>` |
| Alt+# | HTML code-block beautifier | â€” | â€” |

- **Wrapping hotkeys (I, B, C, S):** select text first and the hotkey wraps the selection. With nothing selected, it inserts empty markers and drops the cursor between them.
- **Link wizard:** if you have text selected when you press Alt+L, it's used as the pre-filled link text.
- **Code-block beautifier:** point it at an HTML file (e.g. one rendered from Markdown). Inside any `<code>...</code>` section it replaces tabs with 4 spaces, spaces with `&nbsp;`, and appends `<br />` to each line, then writes the result to `<name>_converted.html` next to the original.

## Usage
Follow this if you do not have AHK installed, if you do feel free to clone / grab pieces out of these scripts and add them to your own!

1. Download the AutoHotkey interpreter from [AutoHotkey website](https://www.autohotkey.com/).
2. Clone or download the contents of this repository to your local machine.
3. Navigate to the AutoHotkeyScripts folder.
4. Open any script file (*.ahk) in a text editor or the AutoHotkey editor.
5. Review the script comments for any customization options or configuration settings.
6. Save the changes to the script file.
7. Double-click on the script file to run it or right-click and select "Run Script".

## Additional Resources
* [Awesome AHK](https://github.com/ahkscript/awesome-AutoHotkey)
