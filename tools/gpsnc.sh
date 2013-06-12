#!/bin/sh
GPSD_LOCAL_PORT=8051
NMEA_REMOTE_PORT=8052

nc -k -l ${NMEA_REMOTE_PORT} | nc -l ${GPSD_LOCAL_PORT} &
gpsd -n -N -D4 tcp://localhost:${GPSD_LOCAL_PORT}
