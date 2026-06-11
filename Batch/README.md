# Batch Scripts

Welcome to the Batch folder! This directory contains a collection of Batch scripts (cmd) designed to automate tasks and perform various functions.

## Scripts
### [bypass_excute_policy_powershell.bat](https://github.com/add1son/AddiScripts/blob/main/Batch/bypass_excute_policy_powershell.bat)

* **Description:** A batch wrapper that temporarily bypasses PowerShell execution policies for a specific script session without altering global system security settings.
* **Functionality:** 
  * **Enforces Admin Rights:** Checks for and requires Administrator privileges before running.
  * **Handles UNC Paths:** Automatically resolves network share mapping using `pushd` and `popd`.
  * **Pre-Flight Check:** Verifies the target `.ps1` file exists locally to prevent unhandled script errors.
  * **Clean Execution:** Launches PowerShell with `-ExecutionPolicy Bypass` and `-NoProfile` to block user profile bloat and ensure an isolated run.
  * **Passes Exit Codes:** Captures the true error/success code of the PowerShell script and returns it to the calling system or RMM automation platform.

## Usage

To run the Batch scripts from the command line:

1. Clone or download the contents of this repository to your local machine.
2. Navigate to the Batch folder.
3. Open a command prompt or terminal.
4. Run each command from the script files line by line by typing them into the command prompt manually and pressing Enter after each line.
   ```cmd
   C:\Path\To\Batch\ScriptName1.bat```
5. Alternatively, execute the .bat files directly by typing their names into the command prompt and pressing Enter.
```ScriptName1.bat```
