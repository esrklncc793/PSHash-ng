function Get-PSHmac {
    <#
    .SYNOPSIS
        Compute an HMAC (Hash-based Message Authentication Code) for strings, bytes, or files.

    .DESCRIPTION
        Get-PSHmac generates HMAC values for API authentication, webhook verification,
        and signature generation. Supports string, byte array, and file inputs.
        Key material is zeroed from memory after use on PowerShell 7+ (.NET 6+).

    .PARAMETER InputObject
        The string to authenticate. Accepts pipeline input.

    .PARAMETER Bytes
        A raw byte array to authenticate.

    .PARAMETER Path
        A file path to authenticate.

    .PARAMETER Key
        The shared secret key as a string (converted to bytes via -KeyEncoding).

    .PARAMETER KeyBytes
        The shared secret key as a raw byte array.

    .PARAMETER KeyEncoding
        Encoding for the -Key string parameter. Default: UTF8.

    .PARAMETER Algorithm
        The hash algorithm for HMAC. Default: SHA256.
        Valid values: MD5, SHA1, SHA256, SHA384, SHA512.

    .PARAMETER OutputFormat
        The output format. Default: Hex.
        Valid values: Hex, Base64, Base64Url.

    .OUTPUTS
        PSHmacResult

    .EXAMPLE
        $mac = Get-PSHmac -InputObject $body -Key $env:GITHUB_WEBHOOK_SECRET -Algorithm SHA256
        "sha256=$($mac.HashLower)" -eq $receivedSignature

    .EXAMPLE
        $slackSig = Get-PSHmac -InputObject "v0:$timestamp`:$body" -Key $signingSecret -OutputFormat Hex

    .EXAMPLE
        $signature = Get-PSHmac -InputObject "$header.$payload" -Key $secret -OutputFormat Base64Url

    .EXAMPLE
        Get-PSHmac -Path ./firmware.bin -Key $deviceKey -Algorithm SHA512

    .NOTES
        On PowerShell 7+ (.NET 6+), HMAC key bytes are zeroed from memory after computation
        using CryptographicOperations.ZeroMemory for enhanced security.
    #>
    [CmdletBinding(DefaultParameterSetName = 'StringKey')]
    [OutputType('PSHmacResult')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'StringKey', Position = 0)]
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'BytesKey',  Position = 0)]
        [AllowEmptyString()]
        [string] $InputObject,

        [Parameter(Mandatory, ParameterSetName = 'BytesInput-StringKey')]
        [Parameter(Mandatory, ParameterSetName = 'BytesInput-BytesKey')]
        [byte[]] $Bytes,

        [Parameter(Mandatory, ParameterSetName = 'FileInput-StringKey')]
        [Parameter(Mandatory, ParameterSetName = 'FileInput-BytesKey')]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'StringKey')]
        [Parameter(Mandatory, ParameterSetName = 'FileInput-StringKey')]
        [Parameter(Mandatory, ParameterSetName = 'BytesInput-StringKey')]
        [string] $Key,

        [Parameter(Mandatory, ParameterSetName = 'BytesKey')]
        [Parameter(Mandatory, ParameterSetName = 'FileInput-BytesKey')]
        [Parameter(Mandatory, ParameterSetName = 'BytesInput-BytesKey')]
        [byte[]] $KeyBytes,

        [Parameter()]
        [ValidateSet('UTF8','UTF16','ASCII','Unicode')]
        [string] $KeyEncoding = 'UTF8',

        [Parameter()]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        [string] $Algorithm = 'SHA256',

        [Parameter()]
        [ValidateSet('Hex','Base64','Base64Url')]
        [string] $OutputFormat = 'Hex'
    )

    process {
        Write-Verbose "Get-PSHmac: Algorithm=$Algorithm, ParameterSet=$($PSCmdlet.ParameterSetName)"

        # Resolve key bytes
        if ($PSCmdlet.ParameterSetName -in @('StringKey','FileInput-StringKey','BytesInput-StringKey')) {
            $enc = switch ($KeyEncoding.ToUpperInvariant()) {
                'UTF8'    { [System.Text.Encoding]::UTF8 }
                'UTF16'   { [System.Text.Encoding]::Unicode }
                'UNICODE' { [System.Text.Encoding]::Unicode }
                'ASCII'   { [System.Text.Encoding]::ASCII }
                default   { [System.Text.Encoding]::UTF8 }
            }
            $keyBytesResolved = $enc.GetBytes($Key)
        }
        else {
            $keyBytesResolved = $KeyBytes
        }

        # Build HMAC algorithm
        $hmac = switch ($Algorithm.ToUpperInvariant()) {
            'MD5'    { [System.Security.Cryptography.HMACMD5]::new($keyBytesResolved) }
            'SHA1'   { [System.Security.Cryptography.HMACSHA1]::new($keyBytesResolved) }
            'SHA256' { [System.Security.Cryptography.HMACSHA256]::new($keyBytesResolved) }
            'SHA384' { [System.Security.Cryptography.HMACSHA384]::new($keyBytesResolved) }
            'SHA512' { [System.Security.Cryptography.HMACSHA512]::new($keyBytesResolved) }
        }

        $hashBytes = $null
        $inputType = 'String'
        try {
            if ($PSCmdlet.ParameterSetName -in @('FileInput-StringKey','FileInput-BytesKey')) {
                # File input
                if (-not (Test-Path -LiteralPath $Path)) {
                    throw [System.IO.FileNotFoundException]::new("File not found: '$Path'.")
                }
                $fs = [System.IO.FileStream]::new(
                    (Resolve-Path $Path).ProviderPath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read
                )
                try {
                    $hashBytes = $hmac.ComputeHash($fs)
                    $inputType = 'File'
                }
                finally {
                    $fs.Dispose()
                }
            }
            elseif ($PSCmdlet.ParameterSetName -in @('BytesInput-StringKey','BytesInput-BytesKey')) {
                $hashBytes = $hmac.ComputeHash($Bytes)
                $inputType = 'Bytes'
            }
            else {
                $inputBytes = Convert-InputToBytes -InputObject $InputObject -Encoding UTF8
                $hashBytes  = $hmac.ComputeHash($inputBytes, 0, $inputBytes.Length)
                $inputType  = 'String'
            }
        }
        finally {
            $hmac.Dispose()

            # Zero key bytes from memory on PS 7+ / .NET 6+
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                try {
                    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory(
                        [System.Runtime.InteropServices.MemoryMarshal]::AsMemory(
                            [System.Memory[byte]] $keyBytesResolved
                        )
                    )
                }
                catch {
                    # Graceful fallback: manually zero the array
                    for ($i = 0; $i -lt $keyBytesResolved.Length; $i++) {
                        $keyBytesResolved[$i] = 0
                    }
                }
            }
        }

        $hexUpper = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
        $hexLower = $hexUpper.ToLowerInvariant()

        $result             = [PSHmacResult]::new()
        $result.Algorithm   = $Algorithm.ToUpperInvariant()
        $result.Hash        = $hexUpper
        $result.HashLower   = $hexLower
        $result.HashBytes   = $hashBytes
        $result.InputType   = $inputType
        $result.KeyLength   = $keyBytesResolved.Length

        switch ($OutputFormat) {
            'Base64'    { return $result.ToBase64() }
            'Base64Url' { return $result.ToBase64Url() }
            default     { return $result }
        }
    }
}
