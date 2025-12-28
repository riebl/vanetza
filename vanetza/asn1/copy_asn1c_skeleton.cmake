if(NOT DEFINED SOURCE)
    set(SOURCE ".")
endif()

file(GLOB asn1c_skeleton_files ${SOURCE}/*.h ${SOURCE}/*.c)
file(COPY ${asn1c_skeleton_files} DESTINATION "${DESTINATION}" PATTERN converter-example.c EXCLUDE)
