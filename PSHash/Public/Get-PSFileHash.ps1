function Get-PSFileHash {
    <#
    .SYNOPSIS
        Enhanced file hashing with multi-algorithm support, parallel execution, and
        pipeline-friendly output.

    .DESCRIPTION
        Get-PSFileHash is a superset of the built-in Get-FileHash cmdlet. Key improvements:
          - Multiple algorithms computed in a single file read (-Algorithm SHA256,SHA512)
          - 64 KB default buffer (vs built-in 4 KB) for better I/O throughput
          - Wildcard and pipeline support (Get-ChildItem *.iso | Get-PSFileHash)
          - -Parallel switch for concurrent multi-file hashing on PS 7+
          - Richer [PSHashResult] output with ToBase64() / ToBase64Url() methods
          - -PassThru to enrich FileInfo objects with Hash properties

    .PARAMETER Path
        One or more file paths. Wildcards are supported. Accepts pipeline input.

    .PARAMETER Algorithm
        One or more hash algorithms to compute. Default: SHA256.
        When multiple algorithms are supplied, each file is read only once.
        Valid values: MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512.

    .PARAMETER BufferSize
        Read buffer size in bytes. Default: 65536 (64 KB).

    .PARAMETER Parallel
        Hash multiple files in parallel using ForEach-Object -Parallel (PS 7+ only).
        Falls back to sequential execution on PS 5.1 with a warning.

    .PARAMETER PassThru
        Emit enriched FileInfo objects (with Hash/Algorithm properties attached)
        instead of [PSHashResult] objects.

    .OUTPUTS
        PSHashResult

    .EXAMPLE
        Get-PSFileHash ./installer.exe

    .EXAMPLE
        Get-PSFileHash ./ubuntu.iso -Algorithm SHA256,SHA512

    .EXAMPLE
        Get-ChildItem C:\releases\*.zip | Get-PSFileHash -Algorithm SHA256 | Export-Csv ./hashes.csv

    .EXAMPLE
        Get-ChildItem /data/*.log | Get-PSFileHash -Parallel

    .EXAMPLE
        Get-ChildItem ./dist | Get-PSFileHash -PassThru | Select-Object Name, Length, Hash

    .NOTES
        The multi-algorithm single-read feature opens each file exactly once regardless of
        how many algorithms are requested, preserving I/O efficiency at scale.
    #>
    [CmdletBinding()]
    [OutputType('PSHashResult')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('FullName')]
        [string[]] $Path,

        [Parameter()]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512','SHA3-256','SHA3-512')]
        [string[]] $Algorithm = @('SHA256'),

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $BufferSize = 65536,

        [Parameter()]
        [switch] $Parallel,

        [Parameter()]
        [switch] $PassThru
    )

    begin {
        $resolvedPaths = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($p in $Path) {
            # Resolve wildcards and pipeline FileInfo objects
            $resolved = Resolve-Path -Path $p -ErrorAction SilentlyContinue
            if ($null -eq $resolved) {
                $PSCmdlet.WriteError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.IO.FileNotFoundException]::new("File not found: '$p'."),
                        'FileNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $p
                    )
                )
                continue
            }
            foreach ($r in $resolved) {
                $resolvedPaths.Add($r.ProviderPath)
            }
        }
    }

    end {
        # Determine if we can use -Parallel (PS 7+ only)
        $useParallel = $Parallel.IsPresent
        if ($useParallel -and $PSVersionTable.PSVersion.Major -lt 7) {
            Write-Warning "Get-PSFileHash: -Parallel requires PowerShell 7+. Falling back to sequential execution."
            $useParallel = $false
        }

        $hashBlock = {
            param([string] $FilePath, [string[]] $Algorithms, [int] $BufSize, [bool] $DoPassThru)

            # Helper: compute multi-algorithm hash in a single file read
            function Invoke-MultiHash {
                param([string] $fp, [string[]] $algos, [int] $bufSize)

                $hashObjects = @{}
                foreach ($alg in $algos) {
                    $hashObjects[$alg] = switch ($alg.ToUpperInvariant()) {
                        'MD5'     { [System.Security.Cryptography.MD5]::Create() }
                        'SHA1'    { [System.Security.Cryptography.SHA1]::Create() }
                        'SHA256'  { [System.Security.Cryptography.SHA256]::Create() }
                        'SHA384'  { [System.Security.Cryptography.SHA384]::Create() }
                        'SHA512'  { [System.Security.Cryptography.SHA512]::Create() }
                        default   {
                            $runtimeVersion = [System.Environment]::Version
                            $typeName = if ($alg -eq 'SHA3-256') {
                                'System.Security.Cryptography.SHA3_256, System.Security.Cryptography'
                            } else {
                                'System.Security.Cryptography.SHA3_512, System.Security.Cryptography'
                            }
                            $t = [System.Type]::GetType($typeName, $false)
                            if ($null -eq $t) {
                                throw [System.NotSupportedException]::new(
                                    "Algorithm '$alg' requires .NET 8 or later (PowerShell 7.4+). Current runtime: $($runtimeVersion.ToString())."
                                )
                            }
                            $t::Create()
                        }
                    }
                }

                $fs = [System.IO.FileStream]::new(
                    $fp,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read,
                    $bufSize
                )
                try {
                    $buf = [byte[]]::new($bufSize)
                    $read = 0
                    while (($read = $fs.Read($buf, 0, $bufSize)) -gt 0) {
                        foreach ($h in $hashObjects.Values) {
                            $h.TransformBlock($buf, 0, $read, $null, 0) | Out-Null
                        }
                    }
                    foreach ($h in $hashObjects.Values) {
                        $h.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
                    }
                }
                finally {
                    $fs.Dispose()
                }

                $results = @{}
                foreach ($alg in $algos) {
                    $results[$alg] = $hashObjects[$alg].Hash
                    $hashObjects[$alg].Dispose()
                }
                return $results
            }

            $fi = [System.IO.FileInfo]::new($FilePath)
            if (-not $fi.Exists) {
                throw [System.IO.FileNotFoundException]::new("File not found: '$FilePath'.")
            }

            $hashes = Invoke-MultiHash -fp $FilePath -algos $Algorithms -bufSize $BufSize

            $outputs = [System.Collections.Generic.List[object]]::new()
            foreach ($alg in $Algorithms) {
                $hashBytes = $hashes[$alg]
                $hexUpper  = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
                $hexLower  = $hexUpper.ToLowerInvariant()

                if ($DoPassThru) {
                    $enriched = $fi | Select-Object *
                    $enriched | Add-Member -NotePropertyName 'Algorithm'  -NotePropertyValue $alg.ToUpperInvariant() -Force
                    $enriched | Add-Member -NotePropertyName 'Hash'       -NotePropertyValue $hexUpper -Force
                    $enriched | Add-Member -NotePropertyName 'HashLower'  -NotePropertyValue $hexLower -Force
                    $enriched | Add-Member -NotePropertyName 'HashBytes'  -NotePropertyValue $hashBytes -Force
                    $outputs.Add($enriched)
                }
                else {
                    $r = [PSHashResult]::new()
                    $r.Algorithm   = $alg.ToUpperInvariant()
                    $r.Hash        = $hexUpper
                    $r.HashLower   = $hexLower
                    $r.HashBytes   = $hashBytes
                    $r.InputType   = 'File'
                    $r.InputLength = $fi.Length
                    $r.Source      = $FilePath
                    $outputs.Add($r)
                }
            }
            return $outputs
        }

        if ($useParallel) {
            # PS 7+ parallel execution
            $algs    = $Algorithm
            $bufSize = $BufferSize
            $pt      = $PassThru.IsPresent

            $resolvedPaths | ForEach-Object -Parallel {
                $fp      = $_
                $algs    = $using:algs
                $bufSize = $using:bufSize
                $pt      = $using:pt

                # Inline the hash logic (parallel runspaces don't share functions)
                $hashObjects = @{}
                foreach ($alg in $algs) {
                    $hashObjects[$alg] = switch ($alg.ToUpperInvariant()) {
                        'MD5'    { [System.Security.Cryptography.MD5]::Create() }
                        'SHA1'   { [System.Security.Cryptography.SHA1]::Create() }
                        'SHA256' { [System.Security.Cryptography.SHA256]::Create() }
                        'SHA384' { [System.Security.Cryptography.SHA384]::Create() }
                        'SHA512' { [System.Security.Cryptography.SHA512]::Create() }
                        default  {
                            $rv = [System.Environment]::Version
                            $tn = if ($alg -eq 'SHA3-256') {
                                'System.Security.Cryptography.SHA3_256, System.Security.Cryptography'
                            } else {
                                'System.Security.Cryptography.SHA3_512, System.Security.Cryptography'
                            }
                            $t = [System.Type]::GetType($tn, $false)
                            if ($null -eq $t) {
                                throw [System.NotSupportedException]::new(
                                    "Algorithm '$alg' requires .NET 8 or later. Current runtime: $($rv.ToString())."
                                )
                            }
                            $t::Create()
                        }
                    }
                }

                $fi = [System.IO.FileInfo]::new($fp)
                $fs = [System.IO.FileStream]::new(
                    $fp,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read,
                    $bufSize
                )
                try {
                    $buf  = [byte[]]::new($bufSize)
                    $read = 0
                    while (($read = $fs.Read($buf, 0, $bufSize)) -gt 0) {
                        foreach ($h in $hashObjects.Values) {
                            $h.TransformBlock($buf, 0, $read, $null, 0) | Out-Null
                        }
                    }
                    foreach ($h in $hashObjects.Values) {
                        $h.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
                    }
                }
                finally {
                    $fs.Dispose()
                }

                foreach ($alg in $algs) {
                    $hashBytes = $hashObjects[$alg].Hash
                    $hashObjects[$alg].Dispose()
                    $hexUpper  = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
                    $hexLower  = $hexUpper.ToLowerInvariant()

                    if ($pt) {
                        $enriched = $fi | Select-Object *
                        $enriched | Add-Member -NotePropertyName 'Algorithm' -NotePropertyValue $alg.ToUpperInvariant() -Force
                        $enriched | Add-Member -NotePropertyName 'Hash'      -NotePropertyValue $hexUpper -Force
                        $enriched | Add-Member -NotePropertyName 'HashLower' -NotePropertyValue $hexLower -Force
                        $enriched | Add-Member -NotePropertyName 'HashBytes' -NotePropertyValue $hashBytes -Force
                        $enriched
                    }
                    else {
                        $r = [PSHashResult]::new()
                        $r.Algorithm   = $alg.ToUpperInvariant()
                        $r.Hash        = $hexUpper
                        $r.HashLower   = $hexLower
                        $r.HashBytes   = $hashBytes
                        $r.InputType   = 'File'
                        $r.InputLength = $fi.Length
                        $r.Source      = $fp
                        $r
                    }
                }
            }
        }
        else {
            # Sequential execution
            foreach ($fp in $resolvedPaths) {
                try {
                    $outputs = & $hashBlock $fp $Algorithm $BufferSize $PassThru.IsPresent
                    foreach ($o in $outputs) { $o }
                }
                catch {
                    $PSCmdlet.WriteError(
                        [System.Management.Automation.ErrorRecord]::new(
                            $_.Exception,
                            'HashComputationError',
                            [System.Management.Automation.ErrorCategory]::InvalidOperation,
                            $fp
                        )
                    )
                }
            }
        }
    }
}
