file(GLOB asn1c_skeleton_files *.h *.c)
file(COPY ${asn1c_skeleton_files} DESTINATION "${DESTINATION}" PATTERN converter-example.c EXCLUDE)
