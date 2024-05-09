# Get list of installed programs
$programs = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate

# Export the list to a CSV file
$programs | Export-Csv -Path "InstalledPrograms.csv" -NoTypeInformation