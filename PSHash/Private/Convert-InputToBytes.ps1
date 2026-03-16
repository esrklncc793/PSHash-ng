function Convert-InputToBytes {
    <#
    .SYNOPSIS
        Normalizes string, byte array, or stream input to a byte array.
    .PARAMETER InputObject
        The input to convert. Accepts [string], [byte[]], or [System.IO.Stream].
    .PARAMETER Encoding
        The text encoding to use when converting a string. Default: UTF8.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [object] $InputObject,

        [Parameter()]
        [ValidateSet('UTF8','UTF16','ASCII','Unicode')]
        [string] $Encoding = 'UTF8'
    )

    # Map encoding name to .NET encoding object
    $enc = switch ($Encoding.ToUpperInvariant()) {
        'UTF8'    { [System.Text.Encoding]::UTF8 }
        'UTF16'   { [System.Text.Encoding]::Unicode }
        'UNICODE' { [System.Text.Encoding]::Unicode }
        'ASCII'   { [System.Text.Encoding]::ASCII }
        default   { [System.Text.Encoding]::UTF8 }
    }

    if ($InputObject -is [byte[]]) {
        Write-Verbose "Convert-InputToBytes: input is byte[], length=$($InputObject.Length)"
        return , [byte[]] $InputObject
    }
    elseif ($InputObject -is [string]) {
        Write-Verbose "Convert-InputToBytes: encoding string as $Encoding"
        $result = $enc.GetBytes([string] $InputObject)
        return , [byte[]] $result
    }
    elseif ($InputObject -is [System.IO.Stream]) {
        Write-Verbose "Convert-InputToBytes: reading from stream"
        $stream = [System.IO.Stream] $InputObject
        # Warn if stream is large (100MB threshold)
        if ($stream.CanSeek -and $stream.Length -gt 104857600) {
            Write-Warning "Stream size ($([math]::Round($stream.Length / 1MB, 1)) MB) exceeds 100 MB — reading entire stream into memory."
        }
        $ms = [System.IO.MemoryStream]::new()
        try {
            $stream.CopyTo($ms)
            return $ms.ToArray()
        }
        finally {
            $ms.Dispose()
        }
    }
    else {
        throw [System.ArgumentException]::new(
            "InputObject must be a [string], [byte[]], or [System.IO.Stream]. Got: $($InputObject.GetType().FullName)"
        )
    }
}
