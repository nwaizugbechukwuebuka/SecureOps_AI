# ---------------------------
# run_mypy.ps1
# ---------------------------

# Activate virtual environment
& .\.venv\Scripts\Activate.ps1
$Env:PYTHONPATH='src'

Write-Host "=== Step 1: Installing missing type stubs ==="
# Install types for common libraries used in your project
pip install --upgrade types-PyYAML types-requests types-setuptools types-python-dateutil -q

Write-Host "=== Step 2: Running mypy ==="
# Run mypy on src folder, show error codes, output to file
$mypyReport = "mypy_report.txt"
mypy src --show-error-codes --pretty | Tee-Object $mypyReport

Write-Host "`n=== Step 3: Summary ==="
# Count errors by type
Get-Content $mypyReport |
    Select-String -Pattern "\[.*\]" |
    ForEach-Object { ($_ -replace ".*\[(.*)\].*", '$1') } |
    Group-Object |
    Sort-Object Count -Descending |
    ForEach-Object { Write-Host "$($_.Count) x $($_.Name)" }

Write-Host "`n✅ Mypy check complete. Full report saved to $mypyReport"
