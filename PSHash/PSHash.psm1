# PSHash.psm1 — Root module loader

# Load classes first (required before private/public functions reference them)
. "$PSScriptRoot/Classes/PSHashClasses.ps1"

# Load private helper functions
Get-ChildItem "$PSScriptRoot/Private/*.ps1" | ForEach-Object { . $_.FullName }

# Load public cmdlets
Get-ChildItem "$PSScriptRoot/Public/*.ps1" | ForEach-Object { . $_.FullName }
