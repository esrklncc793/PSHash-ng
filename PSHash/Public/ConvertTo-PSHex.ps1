function ConvertTo-PSHex {
    <#
    .SYNOPSIS
        Convert a string or byte array to a hexadecimal string representation.

    .DESCRIPTION
        ConvertTo-PSHex encodes strings or byte arrays as hexadecimal strings.
        Supports uppercase output and optional byte-pair delimiters (e.g., colon-separated).

    .PARAMETER InputObject
        The string to convert. Accepts pipeline input.

    .PARAMETER Bytes
        Raw bytes to convert to hex.

    .PARAMETER Encoding
        The string encoding to use. Default: UTF8.
        Valid values: UTF8, UTF16, ASCII, Unicode.

    .PARAMETER Uppercase
        Output uppercase hex digits (default: lowercase).

    .PARAMETER Delimiter
        Insert a delimiter string between each byte pair.
        Example: -Delimiter ':' produces "48:65:6c:6c:6f".

    .OUTPUTS
        System.String

    .EXAMPLE
        "Hello" | ConvertTo-PSHex
        # Returns: 48656c6c6f

    .EXAMPLE
        "Hello" | ConvertTo-PSHex -Uppercase
        # Returns: 48656C6C6F

    .EXAMPLE
        "Hello" | ConvertTo-PSHex -Delimiter ':'
        # Returns: 48:65:6c:6c:6f

    .EXAMPLE
        $bytes | ConvertTo-PSHex
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
        [ValidateSet('UTF8','UTF16','ASCII','Unicode')]
        [string] $Encoding = 'UTF8',

        [Parameter()]
        [switch] $Uppercase,

        [Parameter()]
        [string] $Delimiter = ''
    )

    process {
        $bytesToConvert = if ($PSCmdlet.ParameterSetName -eq 'Bytes') {
            $Bytes
        }
        else {
            Convert-InputToBytes -InputObject $InputObject -Encoding $Encoding
        }

        if ($Delimiter -ne '') {
            # Format each byte individually and join with delimiter
            $parts = $bytesToConvert | ForEach-Object {
                if ($Uppercase) { '{0:X2}' -f $_ } else { '{0:x2}' -f $_ }
            }
            return $parts -join $Delimiter
        }
        else {
            $hex = [System.BitConverter]::ToString($bytesToConvert) -replace '-', ''
            if ($Uppercase) { return $hex } else { return $hex.ToLowerInvariant() }
        }
    }
}
