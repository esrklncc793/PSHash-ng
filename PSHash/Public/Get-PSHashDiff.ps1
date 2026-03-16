function Get-PSHashDiff {
    <#
    .SYNOPSIS
        Compare two files or strings by hash and report whether they are identical.

    .DESCRIPTION
        Get-PSHashDiff hashes two inputs and compares them. Returns a rich diff object
        with Identical, ReferenceHash, DifferenceHash, and Algorithm properties.
        Use -Quiet for a simple boolean result suitable for scripting.

        Input type (file vs string) is auto-detected: if both inputs resolve to existing
        file paths, they are treated as files. Use -AsFile or -AsString to override.

    .PARAMETER ReferenceObject
        The first file path or string to compare.

    .PARAMETER DifferenceObject
        The second file path or string to compare.

    .PARAMETER Algorithm
        The hash algorithm to use for comparison. Default: SHA256.
        Valid values: MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512.

    .PARAMETER AsFile
        Treat both inputs as file paths.

    .PARAMETER AsString
        Treat both inputs as strings.

    .PARAMETER Quiet
        Return a [bool] only instead of the full diff object.

    .OUTPUTS
        PSCustomObject or System.Boolean (with -Quiet)

    .EXAMPLE
        Get-PSHashDiff -ReferenceObject ./original.zip -DifferenceObject ./copy.zip

    .EXAMPLE
        if (-not (Get-PSHashDiff ./a.dll ./b.dll -Quiet)) {
            Write-Warning "DLL mismatch detected!"
        }

    .EXAMPLE
        Get-PSHashDiff -ReferenceObject "config-v1" -DifferenceObject "config-v2" -AsString
    #>
    [CmdletBinding(DefaultParameterSetName = 'Auto')]
    [OutputType([PSCustomObject],[bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $ReferenceObject,

        [Parameter(Mandatory, Position = 1)]
        [string] $DifferenceObject,

        [Parameter()]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512','SHA3-256','SHA3-512')]
        [string] $Algorithm = 'SHA256',

        [Parameter(ParameterSetName = 'File')]
        [switch] $AsFile,

        [Parameter(ParameterSetName = 'String')]
        [switch] $AsString,

        [Parameter()]
        [switch] $Quiet
    )

    # Determine input type
    $treatAsFile = switch ($PSCmdlet.ParameterSetName) {
        'File'   { $true }
        'String' { $false }
        default  {
            # Auto-detect: if both paths exist as files, treat as files
            (Test-Path -LiteralPath $ReferenceObject) -and (Test-Path -LiteralPath $DifferenceObject)
        }
    }

    $refHash  = $null
    $diffHash = $null

    $hashAlg1 = $null
    $hashAlg2 = $null
    try {
        $hashAlg1 = Get-HashAlgorithmInstance -Algorithm $Algorithm
        $hashAlg2 = Get-HashAlgorithmInstance -Algorithm $Algorithm

        if ($treatAsFile) {
            # Hash files
            foreach ($entry in @(@{Path=$ReferenceObject; Alg=$hashAlg1; Var='refHash'},
                                  @{Path=$DifferenceObject; Alg=$hashAlg2; Var='diffHash'})) {
                $resolvedPath = Resolve-Path -LiteralPath $entry.Path -ErrorAction SilentlyContinue
                if ($null -eq $resolvedPath) {
                    throw [System.IO.FileNotFoundException]::new("File not found: '$($entry.Path)'.")
                }
                $fs = [System.IO.FileStream]::new(
                    $resolvedPath.ProviderPath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read
                )
                try {
                    $hashBytes = $entry.Alg.ComputeHash($fs)
                    Set-Variable -Name $entry.Var -Value (([System.BitConverter]::ToString($hashBytes) -replace '-','').ToUpperInvariant())
                }
                finally {
                    $fs.Dispose()
                }
            }
        }
        else {
            # Hash strings
            $refBytes  = Convert-InputToBytes -InputObject $ReferenceObject  -Encoding UTF8
            $diffBytes = Convert-InputToBytes -InputObject $DifferenceObject -Encoding UTF8
            $refHash   = ([System.BitConverter]::ToString($hashAlg1.ComputeHash($refBytes,  0, $refBytes.Length))  -replace '-','').ToUpperInvariant()
            $diffHash  = ([System.BitConverter]::ToString($hashAlg2.ComputeHash($diffBytes, 0, $diffBytes.Length)) -replace '-','').ToUpperInvariant()
        }
    }
    finally {
        if ($null -ne $hashAlg1) { $hashAlg1.Dispose() }
        if ($null -ne $hashAlg2) { $hashAlg2.Dispose() }
    }

    $identical = $refHash -ieq $diffHash

    if ($Quiet) {
        return $identical
    }

    return [PSCustomObject]@{
        Identical       = $identical
        ReferenceHash   = $refHash
        DifferenceHash  = $diffHash
        Algorithm       = $Algorithm.ToUpperInvariant()
        ReferenceInput  = $ReferenceObject
        DifferenceInput = $DifferenceObject
    }
}
