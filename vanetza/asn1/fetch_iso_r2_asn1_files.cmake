if(NOT DIRECTORY)
    message(FATAL_ERROR "DIRECTORY variable is undefined")
endif()
file(MAKE_DIRECTORY "${DIRECTORY}")

file(DOWNLOAD
    "https://standards.iso.org/iso/17573/-3/ed-1/en/ISO17573-3(2023)EfcDataDictionaryV1.3.asn"
    "${DIRECTORY}/ISO17573-3-1.asn")