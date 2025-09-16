# Creates venv if missing, installs dev deps, runs tests with coverage
$venv = ".\.venv"
if (!(Test-Path $venv)) {
  python -m venv .venv
}

# Activate venv for this session
$activate = ".\.venv\Scripts\Activate.ps1"
. $activate

python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pytest --cov=. --cov-report=term-missing
