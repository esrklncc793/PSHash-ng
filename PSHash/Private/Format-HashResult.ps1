function Format-HashResult {
    <#
    .SYNOPSIS
        Builds a [PSHashResult] output object from raw hash bytes and metadata.
    .PARAMETER HashBytes
        The raw hash byte array.
    .PARAMETER Algorithm
        The algorithm name used for hashing.
    .PARAMETER InputType
        One of: 'String', 'File', 'Bytes', 'Stream'.
    .PARAMETER InputLength
        Character count for strings or byte count for bytes/files.
    .PARAMETER Source
        File path if InputType is 'File'; otherwise $null.
    .PARAMETER Encoding
        The encoding used when InputType is 'String'.
    #>
    [CmdletBinding()]
    [OutputType('PSHashResult')]
    param(
        [Parameter(Mandatory)]
        [byte[]] $HashBytes,

        [Parameter(Mandatory)]
        [string] $Algorithm,

        [Parameter(Mandatory)]
        [ValidateSet('String','File','Bytes','Stream')]
        [string] $InputType,

        [Parameter()]
        [long] $InputLength = 0,

        [Parameter()]
        [string] $Source = $null,

        [Parameter()]
        [string] $Encoding = $null
    )

    # Convert bytes to hex strings
    $hexUpper = [System.BitConverter]::ToString($HashBytes) -replace '-', ''
    $hexLower = $hexUpper.ToLowerInvariant()

    $result = [PSHashResult]::new()
    $result.Algorithm   = $Algorithm.ToUpperInvariant()
    $result.Hash        = $hexUpper
    $result.HashLower   = $hexLower
    $result.HashBytes   = $HashBytes
    $result.InputType   = $InputType
    $result.InputLength = $InputLength
    $result.Source      = $Source
    $result.Encoding    = $Encoding

    return $result
}
