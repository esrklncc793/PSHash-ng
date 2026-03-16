class PSHashResult {
    [string] $Algorithm
    [string] $Hash
    [string] $HashLower
    [byte[]] $HashBytes
    [string] $InputType
    [string] $Encoding
    [long]   $InputLength
    [string] $Source

    [string] ToString() { return $this.Hash }

    [string] ToBase64() {
        return [System.Convert]::ToBase64String($this.HashBytes)
    }

    [string] ToBase64Url() {
        return ([System.Convert]::ToBase64String($this.HashBytes) `
            -replace '\+', '-' -replace '/', '_' -replace '=', '')
    }
}

class PSHmacResult {
    [string] $Algorithm
    [string] $Hash
    [string] $HashLower
    [byte[]] $HashBytes
    [string] $InputType
    [int]    $KeyLength

    [string] ToString()    { return $this.Hash }
    [string] ToBase64()    { return [System.Convert]::ToBase64String($this.HashBytes) }
    [string] ToBase64Url() {
        return ([System.Convert]::ToBase64String($this.HashBytes) `
            -replace '\+', '-' -replace '/', '_' -replace '=', '')
    }
}
