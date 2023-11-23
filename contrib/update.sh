#! /usr/bin/env bash

#
# Update the software.
#

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

set -e
#set -x

# Retrieve the update from the repository
git pull origin main --tags
npm ci


# Search for a virtual environment folder in the project root
VENV_NAME="venv"
PROJECT_ROOT=$(pwd)

# Find the virtual environment folder
VENV_PATH=$(find "$PROJECT_ROOT" -type d -name "$VENV_NAME" 2>/dev/null | head -n 1)

if [ -z "$VENV_PATH" ]; then
    echo "Virtual environment not found in the project root."
    exit 1
fi

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

# source env/bin/activate



pip install -e .
# pip install
python manage.py collectstatic --no-input
python manage.py migrate
# python manage.py compilemessages

echo -e "✨ 🌟 ✨"
echo -e "${GREEN}Update finished. You can now restart the service.${NC} Example:"
echo "    sudo systemctl restart apache2.service"

exit 0
