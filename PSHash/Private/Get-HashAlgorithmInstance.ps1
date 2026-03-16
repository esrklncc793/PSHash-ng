function Get-HashAlgorithmInstance {
    <#
    .SYNOPSIS
        Factory function that returns a HashAlgorithm instance by name.
    .PARAMETER Algorithm
        Name of the hash algorithm.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.HashAlgorithm])]
    param(
        [Parameter(Mandatory)]
        [string] $Algorithm
    )

    $validAlgorithms = @('MD5','SHA1','SHA256','SHA384','SHA512','SHA3-256','SHA3-512')

    switch ($Algorithm.ToUpperInvariant()) {
        'MD5'     { return [System.Security.Cryptography.MD5]::Create() }
        'SHA1'    { return [System.Security.Cryptography.SHA1]::Create() }
        'SHA256'  { return [System.Security.Cryptography.SHA256]::Create() }
        'SHA384'  { return [System.Security.Cryptography.SHA384]::Create() }
        'SHA512'  { return [System.Security.Cryptography.SHA512]::Create() }
        'SHA3-256' {
            # SHA3 requires .NET 8+ (PowerShell 7.4+)
            $runtimeVersion = [System.Environment]::Version
            if ($runtimeVersion.Major -lt 8) {
                throw [System.NotSupportedException]::new(
                    ("Algorithm 'SHA3-256' requires .NET 8 or later (PowerShell 7.4+). " +
                     "Current runtime: {0}." -f $runtimeVersion.ToString())
                )
            }
            # Use reflection to access SHA3_256 to avoid compile errors on older .NET
            $sha3Type = [System.Type]::GetType('System.Security.Cryptography.SHA3_256, System.Security.Cryptography', $false)
            if ($null -eq $sha3Type) {
                throw [System.NotSupportedException]::new(
                    ("Algorithm 'SHA3-256' requires .NET 8 or later (PowerShell 7.4+). " +
                     "Current runtime: {0}." -f $runtimeVersion.ToString())
                )
            }
            return $sha3Type::Create()
        }
        'SHA3-512' {
            $runtimeVersion = [System.Environment]::Version
            if ($runtimeVersion.Major -lt 8) {
                throw [System.NotSupportedException]::new(
                    ("Algorithm 'SHA3-512' requires .NET 8 or later (PowerShell 7.4+). " +
                     "Current runtime: {0}." -f $runtimeVersion.ToString())
                )
            }
            $sha3Type = [System.Type]::GetType('System.Security.Cryptography.SHA3_512, System.Security.Cryptography', $false)
            if ($null -eq $sha3Type) {
                throw [System.NotSupportedException]::new(
                    ("Algorithm 'SHA3-512' requires .NET 8 or later (PowerShell 7.4+). " +
                     "Current runtime: {0}." -f $runtimeVersion.ToString())
                )
            }
            return $sha3Type::Create()
        }
        default {
            throw [System.ArgumentException]::new(
                ("Algorithm '{0}' is not supported. Valid values: {1}." -f
                    $Algorithm, ($validAlgorithms -join ', '))
            )
        }
    }
}
