# fix_duplicates_imports.ps1
# Run in your project root (where src/ is)

$srcFolders = "src"

# Regex patterns for functions and classes
$funcPattern = "^\s*def\s+([a-zA-Z0-9_]+)\s*\("
$classPattern = "^\s*class\s+([a-zA-Z0-9_]+)\s*[:\(]"

Get-ChildItem -Path $srcFolders -Recurse -Include *.py | ForEach-Object {
    $file = $_.FullName
    Write-Host "Processing $file..."

    # Read all lines
    $lines = Get-Content $file

    # Separate imports and code
    $importLines = @()
    $codeLines = @()
    foreach ($line in $lines) {
        if ($line -match "^\s*(import|from)\s") {
            $importLines += $line
        } else {
            $codeLines += $line
        }
    }

    # Remove duplicate imports
    $importLines = $importLines | Sort-Object -Unique

    # Remove duplicate functions/classes
    $seen = @{}
    $cleanCode = @()
    $skipBlock = $false

    foreach ($line in $codeLines) {
        if ($line -match $funcPattern) {
            $name = $matches[1]
            if ($seen.ContainsKey($name)) {
                $skipBlock = $true
                $skipBlock = $true
                continue
                $seen[$name] = $true
                $skipBlock = $false
            }
        }
        elseif ($line -match $classPattern) {
            $name = $matches[1]
            if ($seen.ContainsKey($name)) {
                $skipBlock = $true
                continue
            } else {
                $seen[$name] = $true
                $skipBlock = $false
            }
        }

        if (-not $skipBlock) {
            $cleanCode += $line
        }
    }

    # Combine imports and cleaned code
    $finalContent = @($importLines + "" + $cleanCode)
    Set-Content -Path $file -Value $finalContent -Encoding UTF8
}
Write-Host "✅ Finished cleaning imports and duplicates."
