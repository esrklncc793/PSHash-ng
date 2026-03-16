function ConvertFrom-PSHex {
    <#
    .SYNOPSIS
        Decode a hex string back to a string or byte array.

    .DESCRIPTION
        ConvertFrom-PSHex decodes a hexadecimal string into bytes or a text string.
        Automatically strips common delimiters and prefixes: whitespace, colons, dashes,
        and leading 0x prefix. Throws clear errors for invalid hex input.

    .PARAMETER InputObject
        The hex string to decode. Accepts pipeline input.
        Delimiters (colons, dashes, spaces) and 0x prefix are stripped automatically.

    .PARAMETER AsBytes
        Return a [byte[]] instead of a decoded string.

    .PARAMETER Encoding
        The string encoding for the output string. Default: UTF8.
        Valid values: UTF8, UTF16, ASCII, Unicode.

    .OUTPUTS
        System.String or System.Byte[]

    .EXAMPLE
        "48656c6c6f" | ConvertFrom-PSHex
        # Returns: Hello

    .EXAMPLE
        "48:65:6c:6c:6f" | ConvertFrom-PSHex
        # Returns: Hello

    .EXAMPLE
        "0x48656c6c6f" | ConvertFrom-PSHex
        # Returns: Hello

    .EXAMPLE
        "deadbeef" | ConvertFrom-PSHex -AsBytes
        # Returns: [byte[]] 0xDE 0xAD 0xBE 0xEF
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
        [string] $Encoding = 'UTF8'
    )

    process {
        $hexStr = $InputObject

        # Strip 0x / 0X prefix
        if ($hexStr -match '^0[xX]') {
            $hexStr = $hexStr.Substring(2)
        }

        # Strip whitespace, colons, dashes (common delimiters)
        $hexStr = $hexStr -replace '[\s:\-]', ''

        # Validate: must be even length
        if ($hexStr.Length % 2 -ne 0) {
            throw [System.FormatException]::new(
                "Invalid hex string: length $($hexStr.Length) is odd. Hex strings must have an even number of characters."
            )
        }

        # Validate: only hex characters allowed
        for ($i = 0; $i -lt $hexStr.Length; $i++) {
            $c = $hexStr[$i]
            if (-not (($c -ge '0' -and $c -le '9') -or
                      ($c -ge 'a' -and $c -le 'f') -or
                      ($c -ge 'A' -and $c -le 'F'))) {
                throw [System.FormatException]::new(
                    "Invalid hex string: character '$c' at position $i is not a valid hex digit."
                )
            }
        }

        # Decode hex to byte array
        $bytes = [byte[]]::new($hexStr.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [System.Convert]::ToByte($hexStr.Substring($i * 2, 2), 16)
        }

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
