<#
.SYNOPSIS
    Exports full detail on every Scheduled Task for server migration purposes.

.DESCRIPTION
    Pulls every task (all folders, all states) and produces two outputs:
      1. A flattened CSV with as much human-readable detail as possible —
         name, path, state, author, description, run-as account, run level,
         triggers, action, last run,
         last result, next run.
      2. A folder of native .xml exports (one per task, via Export-ScheduledTask)
         preserving full fidelity — these can be re-imported on the new server
         with Register-ScheduledTask -Xml, no rebuilding by hand required.

.PARAMETER OutputDir
    Root folder for output. Defaults to a timestamped folder on the Desktop.

.PARAMETER TaskPathFilter
    Optional wildcard filter on task path, e.g. "\ClientX\*". Default is everything.

.EXAMPLE
    .\Export-ScheduledTasks.ps1
    .\Export-ScheduledTasks.ps1 -OutputDir "C:\Migration\TaskSchedulerExport" -TaskPathFilter "\ClientX\*"
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "$env:USERPROFILE\Desktop\TaskSchedulerExport_$(Get-Date -Format yyyyMMdd_HHmmss)",
    [string]$TaskPathFilter = "*"
)

$xmlDir = Join-Path $OutputDir "XML"
New-Item -ItemType Directory -Path $xmlDir -Force | Out-Null
$csvPath = Join-Path $OutputDir "ScheduledTasks_Inventory.csv"

function Get-TriggerSummary {
    param($Triggers)

    if (-not $Triggers) { return "(none)" }

    $summaries = foreach ($t in $Triggers) {
        $type = $t.CimClass.CimClassName -replace 'MSFT_Task', '' -replace 'Trigger', ''
        $enabled = if ($t.Enabled) { "Enabled" } else { "Disabled" }

        $detail = switch ($type) {
            "Time"          { "StartBoundary=$($t.StartBoundary)" }
            "Daily"         { "Every $($t.DaysInterval) day(s), Start=$($t.StartBoundary)" }
            "Weekly"        { "DaysOfWeek=$($t.DaysOfWeek), Start=$($t.StartBoundary)" }
            "Monthly"       { "DaysOfMonth=$($t.DaysOfMonth), Months=$($t.MonthsOfYear), Start=$($t.StartBoundary)" }
            "Logon"         { "At logon, UserId=$($t.UserId)" }
            "Boot"          { "At system boot" }
            "Idle"          { "On idle" }
            "Registration"  { "At task registration/update" }
            "SessionState"  { "StateChange=$($t.StateChange), UserId=$($t.UserId)" }
            default         { "StartBoundary=$($t.StartBoundary)" }
        }

        "$type [$enabled]: $detail"
    }

    return ($summaries -join " | ")
}

function Get-ActionSummary {
    param($Actions)

    if (-not $Actions) { return "(none)" }

    $summaries = foreach ($a in $Actions) {
        switch ($a.CimClass.CimClassName) {
            "MSFT_TaskExecAction" {
                "Execute: `"$($a.Execute)`" Args: `"$($a.Arguments)`" WorkingDir: `"$($a.WorkingDirectory)`""
            }
            "MSFT_TaskComHandlerAction" {
                "COM Handler: ClassId=$($a.ClassId) Data=$($a.Data)"
            }
            "MSFT_TaskEmailAction" {
                "Email (deprecated action type): To=$($a.To)"
            }
            default {
                "Unknown action type: $($a.CimClass.CimClassName)"
            }
        }
    }

    return ($summaries -join " | ")
}

Write-Host "Gathering tasks matching path filter '$TaskPathFilter'..."
$allTasks = Get-ScheduledTask -TaskPath $TaskPathFilter

if (-not $allTasks) {
    Write-Warning "No tasks found matching that filter."
    return
}

Write-Host "Found $($allTasks.Count) task(s). Building inventory..."

$inventory = foreach ($task in $allTasks) {

    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

    # Export native XML for exact re-import on the new box.
    # Sanitize path into a safe filename: strip leading slash, replace remaining slashes.
    $safeName = ($task.TaskPath.TrimStart('\') + $task.TaskName) -replace '[\\\/]', '_'
    $xmlFile  = Join-Path $xmlDir "$safeName.xml"

    try {
        Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath |
            Out-File -FilePath $xmlFile -Encoding unicode
    }
    catch {
        Write-Warning "Failed to export XML for $($task.TaskPath)$($task.TaskName): $($_.Exception.Message)"
    }

    [PSCustomObject]@{
        TaskPath        = $task.TaskPath
        TaskName        = $task.TaskName
        FullPath        = "$($task.TaskPath)$($task.TaskName)"
        State           = $task.State
        Enabled         = $task.Settings.Enabled
        Author          = $task.Author
        Description     = $task.Description
        RunAsUser       = $task.Principal.UserId
        RunLevel        = $task.Principal.RunLevel
        LogonType       = $task.Principal.LogonType
        Triggers        = Get-TriggerSummary $task.Triggers
        Actions         = Get-ActionSummary $task.Actions
        AllowOnDemand   = $task.Settings.AllowDemandStart
        StartWhenAvail  = $task.Settings.StartWhenAvailable
        Hidden          = $task.Settings.Hidden
        ExecutionLimit  = $task.Settings.ExecutionTimeLimit
        LastRunTime     = $info.LastRunTime
        LastTaskResult  = if ($info) { "0x{0:X}" -f $info.LastTaskResult } else { $null }
        NextRunTime     = $info.NextRunTime
        NumberOfMissedRuns = $info.NumberOfMissedRuns
        SourceXml       = $xmlFile
    }
}

$inventory | Sort-Object FullPath | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Done."
Write-Host "CSV inventory : $csvPath"
Write-Host "XML exports   : $xmlDir  ($($allTasks.Count) file(s))"