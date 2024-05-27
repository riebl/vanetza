#!/bin/bash -eu
afl-system-config

usermod -u ${HOST_USER_ID} -g ${HOST_GROUP_ID} fuzz
ln -sf /source /home/fuzz/source
ln -sf /input /home/fuzz/input
ln -sf /output /home/fuzz/output
ln -sf /source/tools/fuzz-harness/compile.sh /home/fuzz/compile.sh
ln -sf /source/tools/fuzz-harness/fuzz.sh /home/fuzz/fuzz.sh
cd /home/fuzz
su fuzz
