#!/bin/bash

# Getting script directory.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Saving origin path.
ORIGDIR=$(pwd)

# Cleaning old .pyc files to not run into the "importing seems to work" trap again!
find ${DIR} -name "*.pyc" -exec rm {} \;

# Changing to the root path of th application.
cd ${DIR}

# Checking if PYWISHLIST_CFG is set. If not, use the provided example file.
if [ -z "$PYWISHLIST_CFG" ]; then
	if [ -f "dist/pywishlist.cfg" ]; then
		echo "Setting PYWISHLIST_CFG for you. Please use your own settings for production!"
		export PYWISHLIST_CFG="../dist/pywishlist.cfg"
	else
		export PYWISHLIST_CFG="../dist/pywishlist.cfg.example"
	fi
fi

# Activating virtualenv
source venv/bin/activate

# Actually starting the application.
python pywishlist.py

# Deactivating virtualenv
deactivate

# Changing back to origin path.
cd ${ORIGDIR}