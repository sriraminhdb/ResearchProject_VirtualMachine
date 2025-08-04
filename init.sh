#!/usr/bin/env bash
set -e

# 1. Create & activate venv
if command -v python3 &>/dev/null; then
  python3 -m venv venv
  source venv/bin/activate
elif command -v py &>/dev/null; then
  py -3 -m venv venv
  source venv/Scripts/activate
else
  echo "ERROR: Python not found." >&2
  exit 1
fi

# 1.5 Add project root to PYTHONPATH so pytest can see backend/
export PYTHONPATH="$(pwd)"

# 2. Upgrade pip & install deps
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 3. Init Git if needed
if [ ! -d .git ]; then
  git init
fi

# 4. Write .gitignore
cat > .gitignore <<EOF
venv/
__pycache__/
*.py[cod]
*.so
EOF

# 5. Commit
git add .
git commit -m "chore: initial project bootstrap"
echo "✅ Done. Virtualenv active; PYTHONPATH set to project root."
