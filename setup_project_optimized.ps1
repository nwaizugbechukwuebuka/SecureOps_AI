# --- setup_project_optimized.ps1 ---
# 1?? Activate virtual environment
& ".\.venv\Scripts\Activate.ps1"

# 2?? Upgrade pip, setuptools, wheel
python -m pip install --upgrade pip setuptools wheel

# 3?? Fix requirements and save to a new file
(Get-Content requirements.txt) 
    -replace 'psycopg2==\d+\.\d+\.\d+', 'psycopg2-binary==2.9.11' 
    -replace 'cryptography==\d+\.\d+\.\d+', 'cryptography==43.0.3' 
    -replace 'github==\d+\.\d+\.\d+', 'github3.py==1.3.0' 
    -replace 'trivy-python==\d+\.\d+\.\d+', '' | Set-Content requirements_fixed.txt

# 4?? Install fixed dependencies
python -m pip install -r requirements_fixed.txt --upgrade --no-cache-dir

# 5?? Ensure prometheus_client is installed
python -m pip install prometheus_client --upgrade

# 6?? Verify SQLAlchemy
python -c "import sqlalchemy; print('SQLAlchemy version:', sqlalchemy.__version__)"

# 7?? Run FastAPI via Uvicorn
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 9000 --reload
