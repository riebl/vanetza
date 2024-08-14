if(NOT DEFINED ASN1C_OUTPUT_DIR)
    message(FATAL_ERROR "Missing ASN.1 output directory (ASN1C_OUTPUT_DIR)")
elseif(NOT DEFINED ASN1C_PREFIX)
    message(FATAL_ERROR "Missing ASN.1 prefix (ASN1C_PREFIX)")
endif()

message(STATUS "removing prefix '${ASN1C_PREFIX}' from files in ${ASN1C_OUTPUT_DIR}")
file(GLOB _files RELATIVE ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_CURRENT_LIST_DIR}/${ASN1C_OUTPUT_DIR}/${ASN1C_PREFIX}*)
foreach(_from ${_files})
    string(REPLACE "${ASN1C_PREFIX}" "" _to "${_from}")
    file(RENAME ${_from} ${_to})
endforeach()

