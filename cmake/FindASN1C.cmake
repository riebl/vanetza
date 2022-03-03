find_program(ASN1C_EXECUTABLE NAMES asn1c DOC "ASN.1 compiler")
if(ASN1C_EXECUTABLE)
    execute_process(COMMAND ${ASN1C_EXECUTABLE} -version ERROR_VARIABLE _asn1c_version)
    string(REGEX MATCH "[0-9]\\.[0-9]\\.[0-9]+" ASN1C_VERSION "${_asn1c_version}")
    get_filename_component(_asn1c_executable_path ${ASN1C_EXECUTABLE} DIRECTORY)
endif()

find_path(ASN1C_SKELETON_DIR NAMES asn_application.c
    HINTS "${_asn1c_executable_path}/.."
    PATH_SUFFIXES share/asn1c skeletons
    DOC "Directory containing generic asn1c skeleton files")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ASN1C
    REQUIRED_VARS ASN1C_EXECUTABLE ASN1C_SKELETON_DIR
    FOUND_VAR ASN1C_FOUND
    VERSION_VAR ASN1C_VERSION)

mark_as_advanced(ASN1C_EXECUTABLE ASN1C_SKELETON_DIR)
