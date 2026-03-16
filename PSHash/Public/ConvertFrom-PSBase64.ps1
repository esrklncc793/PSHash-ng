function ConvertFrom-PSBase64 {
    <#
    .SYNOPSIS
        Decode a Base64 or Base64URL string back to a string or byte array.

    .DESCRIPTION
        ConvertFrom-PSBase64 decodes standard Base64 or Base64URL (URL-safe) strings.
        Auto-detects URL-safe format by checking for - or _ characters, so -UrlSafe is
        optional unless you need to force URL-safe interpretation.

    .PARAMETER InputObject
        The Base64 or Base64URL string to decode. Accepts pipeline input.

    .PARAMETER AsBytes
        Return a [byte[]] instead of a decoded string.

    .PARAMETER Encoding
        The string encoding to use for output. Default: UTF8.
        Valid values: UTF8, UTF16, ASCII, Unicode.

    .PARAMETER UrlSafe
        Explicitly treat the input as Base64URL (overrides auto-detection).

    .OUTPUTS
        System.String or System.Byte[]

    .EXAMPLE
        "SGVsbG8gV29ybGQ=" | ConvertFrom-PSBase64
        # Returns: Hello World

    .EXAMPLE
        "eyJhbGciOiJIUzI1NiJ9" | ConvertFrom-PSBase64 -UrlSafe

    .EXAMPLE
        $rawBytes = "AQID..." | ConvertFrom-PSBase64 -AsBytes
    #>
    [CmdletBinding()]
    [OutputType([string],[byte[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string] $InputObject,

        [Parameter()]
        [switch] $AsBytes,

        [Parameter()]
        [ValidateSet('UTF8','UTF16','ASCII','Unicode')]
        [string] $Encoding = 'UTF8',

        [Parameter()]
        [switch] $UrlSafe
    )

    process {
        $input64 = $InputObject

        # Auto-detect URL-safe Base64 if it contains - or _
        $isUrlSafe = $UrlSafe.IsPresent -or ($input64 -match '[-_]')

        if ($isUrlSafe) {
            # Convert URL-safe chars back to standard Base64
            $input64 = $input64 -replace '-', '+' -replace '_', '/'
        }

        # Re-add padding if needed
        $padNeeded = (4 - ($input64.Length % 4)) % 4
        $input64 += '=' * $padNeeded

        $bytes = [System.Convert]::FromBase64String($input64)

        if ($AsBytes) {
            return , $bytes
        }

        $enc = switch ($Encoding.ToUpperInvariant()) {
            'UTF8'    { [System.Text.Encoding]::UTF8 }
            'UTF16'   { [System.Text.Encoding]::Unicode }
            'UNICODE' { [System.Text.Encoding]::Unicode }
            'ASCII'   { [System.Text.Encoding]::ASCII }
            default   { [System.Text.Encoding]::UTF8 }
        }

        return $enc.GetString($bytes)
    }
}
