@{
    ModuleVersion     = '1.0.0'
    GUID              = 'a3f8c2d1-4e7b-4a9f-b6e1-2c5d8f9a0e3b'
    Author            = 'PSHash Contributors'
    CompanyName       = ''
    Copyright         = '(c) PSHash Contributors. All rights reserved.'
    Description       = 'A comprehensive hashing, HMAC, encoding, and checksum toolkit for PowerShell. Fills the gaps left by Get-FileHash with string hashing, HMAC, Base64URL, hex encoding, parallel file hashing, and checksum verification.'
    PowerShellVersion = '5.1'
    RootModule        = 'PSHash.psm1'

    FunctionsToExport = @(
        'Get-PSHash',
        'Get-PSFileHash',
        'Get-PSHmac',
        'Test-PSChecksum',
        'ConvertTo-PSBase64',
        'ConvertFrom-PSBase64',
        'ConvertTo-PSHex',
        'ConvertFrom-PSHex',
        'Get-PSHashDiff'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags        = @('hash','hmac','sha256','base64','hex','checksum','encoding','security','cryptography','integrity','jwt','DevOps')
            ProjectUri  = 'https://github.com/yourname/PSHash'
            LicenseUri  = 'https://github.com/yourname/PSHash/blob/main/LICENSE'
            ReleaseNotes = 'Initial release of PSHash — a comprehensive hashing and encoding toolkit.'
        }
    }
}
