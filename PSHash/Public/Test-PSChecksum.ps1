function Test-PSChecksum {
    <#
    .SYNOPSIS
        Verify a file or string against an expected hash value.

    .DESCRIPTION
        Test-PSChecksum computes the hash of the input and compares it against the
        expected value. Returns $true or $false (or the original input with -PassThru
        on match). Auto-detects hex, Base64, and Base64URL formats in -ExpectedHash.

    .PARAMETER Path
        The file path to verify.

    .PARAMETER InputObject
        The string to verify.

    .PARAMETER ExpectedHash
        The expected hash value. Accepted formats: hex, Base64, Base64URL (auto-detected).

    .PARAMETER Algorithm
        The hash algorithm to use. Default: SHA256.
        Valid values: MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512.

    .PARAMETER PassThru
        On a successful match, emit the file path or input object downstream.

    .PARAMETER Encoding
        The text encoding for string hashing. Default: UTF8.

    .PARAMETER CaseSensitive
        Force case-sensitive hex comparison. Default: case-insensitive.

    .OUTPUTS
        System.Boolean or the input object (with -PassThru on match)

    .EXAMPLE
        Test-PSChecksum -Path ./ubuntu-24.04.iso -ExpectedHash "a4acfda10b18da50..."

    .EXAMPLE
        if (-not (Test-PSChecksum ./pkg.zip -ExpectedHash $publishedSha256)) {
            throw "Checksum mismatch!"
        }

    .EXAMPLE
        Get-ChildItem ./received/ | Test-PSChecksum -ExpectedHash $knownGoodHash -PassThru | Move-Item -Destination ./verified/

    .EXAMPLE
        Test-PSChecksum -InputObject "config-v1.0" -ExpectedHash $storedHash -Algorithm SHA256
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'File', Position = 0)]
        [Alias('FullName')]
        [string] $Path,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'String', Position = 0)]
        [AllowEmptyString()]
        [string] $InputObject,

        [Parameter(Mandatory, Position = 1)]
        [string] $ExpectedHash,

        [Parameter()]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512','SHA3-256','SHA3-512')]
        [string] $Algorithm = 'SHA256',

        [Parameter()]
        [switch] $PassThru,

        [Parameter()]
        [ValidateSet('UTF8','UTF16','ASCII','Unicode')]
        [string] $Encoding = 'UTF8',

        [Parameter()]
        [switch] $CaseSensitive
    )

    process {
        # Normalize the expected hash to uppercase hex for comparison
        $normalizedExpected = $null

        # Detect format: Base64URL (contains - or _), Base64 (contains + / =), or hex (default)
        if ($ExpectedHash -match '[-_]') {
            # Base64URL — convert to hex
            $padded = $ExpectedHash -replace '-', '+' -replace '_', '/'
            $padNeeded = (4 - ($padded.Length % 4)) % 4
            $padded += '=' * $padNeeded
            $bytes = [System.Convert]::FromBase64String($padded)
            $normalizedExpected = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToUpperInvariant()
        }
        elseif ($ExpectedHash -match '[+/=]') {
            # Contains explicit Base64 characters — standard Base64
            try {
                $bytes = [System.Convert]::FromBase64String($ExpectedHash)
                $normalizedExpected = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToUpperInvariant()
            }
            catch {
                # Not valid Base64, treat as hex
                $normalizedExpected = $ExpectedHash.ToUpperInvariant()
            }
        }
        else {
            # Default: assume hex string
            $normalizedExpected = $ExpectedHash.ToUpperInvariant()
        }

        # Compute the actual hash
        $hashAlg = $null
        try {
            $hashAlg = Get-HashAlgorithmInstance -Algorithm $Algorithm

            if ($PSCmdlet.ParameterSetName -eq 'File') {
                $resolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
                if ($null -eq $resolvedPath) {
                    $PSCmdlet.WriteError(
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.IO.FileNotFoundException]::new("File not found: '$Path'."),
                            'FileNotFound',
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            $Path
                        )
                    )
                    return
                }
                $fs = [System.IO.FileStream]::new(
                    $resolvedPath.ProviderPath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read
                )
                try {
                    $hashBytes = $hashAlg.ComputeHash($fs)
                }
                finally {
                    $fs.Dispose()
                }
                $actualHex = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToUpperInvariant()
            }
            else {
                $inputBytes = Convert-InputToBytes -InputObject $InputObject -Encoding $Encoding
                $hashBytes  = $hashAlg.ComputeHash($inputBytes, 0, $inputBytes.Length)
                $actualHex  = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToUpperInvariant()
            }
        }
        finally {
            if ($null -ne $hashAlg) { $hashAlg.Dispose() }
        }

        # Compare
        $match = if ($CaseSensitive) {
            $actualHex -ceq $normalizedExpected
        }
        else {
            $actualHex -ieq $normalizedExpected
        }

        Write-Verbose "Test-PSChecksum: actual=$actualHex, expected=$normalizedExpected, match=$match"

        if ($PassThru) {
            if ($match) {
                if ($PSCmdlet.ParameterSetName -eq 'File') {
                    return $Path
                }
                else {
                    return $InputObject
                }
            }
            # No output on mismatch with -PassThru
        }
        else {
            return $match
        }
    }
}
