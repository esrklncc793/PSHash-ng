function ConvertTo-PSBase64 {
    <#
    .SYNOPSIS
        Encode a string or byte array to Base64 or Base64URL.

    .DESCRIPTION
        ConvertTo-PSBase64 encodes strings or byte arrays using standard RFC 4648 Base64
        or the URL-safe Base64URL variant (replaces + with -, / with _, strips = padding).
        Base64URL is used in JWTs, OAuth tokens, and URL-safe identifiers.

    .PARAMETER InputObject
        The string to encode. Accepts pipeline input.

    .PARAMETER Bytes
        Raw bytes to encode.

    .PARAMETER UrlSafe
        Output Base64URL (replaces + with -, / with _, strips = padding).

    .PARAMETER Encoding
        The string encoding to use. Default: UTF8.
        Valid values: UTF8, UTF16, ASCII, Unicode.

    .PARAMETER NoPadding
        Strip = padding from standard Base64 output.

    .OUTPUTS
        System.String

    .EXAMPLE
        "Hello World" | ConvertTo-PSBase64
        # Returns: SGVsbG8gV29ybGQ=

    .EXAMPLE
        '{"alg":"HS256","typ":"JWT"}' | ConvertTo-PSBase64 -UrlSafe

    .EXAMPLE
        $bytes | ConvertTo-PSBase64 -Bytes

    .EXAMPLE
        @("Alice","Bob") | ConvertTo-PSBase64
    #>
    [CmdletBinding(DefaultParameterSetName = 'String')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'String', Position = 0)]
        [AllowEmptyString()]
        [string] $InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [byte[]] $Bytes,

        [Parameter()]
        [switch] $UrlSafe,

        [Parameter()]
        [ValidateSet('UTF8','UTF16','ASCII','Unicode')]
        [string] $Encoding = 'UTF8',

        [Parameter()]
        [switch] $NoPadding
    )

    process {
        $bytesToEncode = if ($PSCmdlet.ParameterSetName -eq 'Bytes') {
            $Bytes
        }
        else {
            Convert-InputToBytes -InputObject $InputObject -Encoding $Encoding
        }

        $b64 = [System.Convert]::ToBase64String($bytesToEncode)

        if ($UrlSafe) {
            # URL-safe: replace + -> -, / -> _, strip = padding
            return ($b64 -replace '\+', '-' -replace '/', '_' -replace '=', '')
        }
        elseif ($NoPadding) {
            return ($b64 -replace '=', '')
        }
        else {
            return $b64
        }
    }
}
