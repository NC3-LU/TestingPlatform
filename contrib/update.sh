#! /usr/bin/env bash

#
# Update the software.
#

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

set -e
#set -x

git pull origin main --tags
npm ci
. env/bin/activate
# pip install -e .
pip install
python manage.py collectstatic --no-input
python manage.py migrate
# python manage.py compilemessages

echo -e "✨ 🌟 ✨"
echo -e "${GREEN}Update finished. You can now restart the service.${NC} Example:"
echo "    sudo systemctl restart apache2.service"

exit 0
