function Get-PSHash {
    <#
    .SYNOPSIS
        Compute a cryptographic hash of a string, byte array, or stream.

    .DESCRIPTION
        Get-PSHash computes a cryptographic hash of a string, byte array, or stream using
        the specified algorithm. This fills the gap left by Get-FileHash, which only works
        with files. Supports MD5, SHA1, SHA256, SHA384, SHA512, and SHA3-256/SHA3-512
        (on .NET 8+ / PowerShell 7.4+).

    .PARAMETER InputObject
        The string to hash. Accepts pipeline input.

    .PARAMETER Bytes
        A raw byte array to hash.

    .PARAMETER Stream
        A System.IO.Stream to hash.

    .PARAMETER Algorithm
        The hash algorithm to use. Default: SHA256.
        Valid values: MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512.

    .PARAMETER Encoding
        The text encoding to use when hashing a string. Default: UTF8.
        Valid values: UTF8, UTF16, ASCII, Unicode.

    .PARAMETER OutputFormat
        The output format for the hash. Default: Hex.
        Valid values: Hex, Base64, Base64Url.

    .OUTPUTS
        PSHashResult

    .EXAMPLE
        "Hello World" | Get-PSHash

    .EXAMPLE
        Get-PSHash -InputObject "Hello World" -Algorithm SHA512 -Encoding UTF8

    .EXAMPLE
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("secret")
        Get-PSHash -Bytes $bytes -Algorithm SHA256

    .EXAMPLE
        "api-key-data" | Get-PSHash -OutputFormat Base64Url

    .EXAMPLE
        @("Alice","Bob","Carol") | Get-PSHash | Select-Object Hash, InputLength

    .NOTES
        Empty strings are valid input — they produce a well-defined hash value.
    #>
    [CmdletBinding(DefaultParameterSetName = 'String')]
    [OutputType('PSHashResult')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'String', Position = 0)]
        [AllowEmptyString()]
        [string] $InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [byte[]] $Bytes,

        [Parameter(Mandatory, ParameterSetName = 'Stream')]
        [System.IO.Stream] $Stream,

        [Parameter()]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512','SHA3-256','SHA3-512')]
        [string] $Algorithm = 'SHA256',

        [Parameter()]
        [ValidateSet('UTF8','UTF16','ASCII','Unicode')]
        [string] $Encoding = 'UTF8',

        [Parameter()]
        [ValidateSet('Hex','Base64','Base64Url')]
        [string] $OutputFormat = 'Hex'
    )

    process {
        Write-Verbose "Get-PSHash: Algorithm=$Algorithm, ParameterSet=$($PSCmdlet.ParameterSetName)"

        $hashAlg = $null
        try {
            $hashAlg = Get-HashAlgorithmInstance -Algorithm $Algorithm

            switch ($PSCmdlet.ParameterSetName) {
                'String' {
                    $inputBytes = Convert-InputToBytes -InputObject $InputObject -Encoding $Encoding
                    if ($null -eq $inputBytes) { $inputBytes = [byte[]]::new(0) }
                    $hashBytes  = $hashAlg.ComputeHash($inputBytes, 0, $inputBytes.Length)
                    $result     = Format-HashResult -HashBytes $hashBytes `
                                                    -Algorithm $Algorithm `
                                                    -InputType 'String' `
                                                    -InputLength $InputObject.Length `
                                                    -Encoding $Encoding
                }
                'Bytes' {
                    $hashBytes = $hashAlg.ComputeHash($Bytes)
                    $result    = Format-HashResult -HashBytes $hashBytes `
                                                   -Algorithm $Algorithm `
                                                   -InputType 'Bytes' `
                                                   -InputLength $Bytes.Length
                }
                'Stream' {
                    $inputBytes = Convert-InputToBytes -InputObject $Stream
                    $hashBytes  = $hashAlg.ComputeHash($inputBytes)
                    $result     = Format-HashResult -HashBytes $hashBytes `
                                                    -Algorithm $Algorithm `
                                                    -InputType 'Stream' `
                                                    -InputLength $inputBytes.Length
                }
            }
        }
        finally {
            if ($null -ne $hashAlg) { $hashAlg.Dispose() }
        }

        # Apply output format transformation if requested
        switch ($OutputFormat) {
            'Base64'    { return $result.ToBase64() }
            'Base64Url' { return $result.ToBase64Url() }
            default     { return $result }
        }
    }
}
