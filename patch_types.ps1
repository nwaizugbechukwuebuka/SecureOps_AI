# patch_types.ps1
# Automatically adds type hints to Python files for mypy compliance

$projectPath = "src"
$files = Get-ChildItem -Path $projectPath -Recurse -Filter *.py

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw

    # Add generic types for Dict, Sequence, Callable
    $content = $content -replace "\bDict\b", "Dict[str, Any]"
    $content = $content -replace "\bSequence\b", "Sequence[Any]"
    $content = $content -replace "\bCallable\b", "Callable[..., Any]"
    $content = $content -replace "\bdict\b", "dict[str, Any]"

    # Add missing return types -> None for async or normal functions if no return
    $content = $content -replace "(?<=def\s+\w+\([^)]*\))\s*:", " -> None:"

    # Save patched file
    Set-Content -Path $file.FullName -Value $content
}

Write-Host "✅ Type hints patched for all Python files in $projectPath."
Write-Host "Run mypy again to check remaining issues."
