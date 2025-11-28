# Run tests on Windows with the correct PYTHONPATH set to `src`.
Param()

Write-Output "Setting PYTHONPATH=src and running pytest..."
$Env:PYTHONPATH = 'src'
pytest -q

if ($LASTEXITCODE -ne 0) {
    Write-Error "pytest failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
Write-Output "All tests passed."
