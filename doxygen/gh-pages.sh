#!/bin/bash
cd "$(git rev-parse --show-toplevel)"
doxygen
rsync --delete --recursive doxygen/html/ www/doxygen/
