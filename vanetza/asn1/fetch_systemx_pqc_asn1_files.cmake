if(NOT OUTPUT_DIRECTORY)
    message(FATAL_ERROR "OUTPUT_DIRECTORY is undefined")
endif()
if(NOT PATCH_FILE)
    message(FATAL_ERROR "PATCH_FILE is undefined")
endif()

set(_etsi_revision "65e6d8ea88b2bfb3aca3151dbedf07d89b97fd00")
set(_ieee_revision "77e2c822a11bf8adbe9848ad3fd4f311925aff30")
set(_etsi_repository "https://forge.etsi.org/rep/ITS/asn1/sec_ts103097")
set(_ieee_repository "https://forge.etsi.org/rep/ITS/asn1/ieee1609.2")

function(download_module REPOSITORY REVISION MODULE SHA256)
    set(_url "${REPOSITORY}/-/raw/${REVISION}/${MODULE}")
    set(_output "${OUTPUT_DIRECTORY}/${MODULE}")
    file(DOWNLOAD "${_url}" "${_output}"
        EXPECTED_HASH "SHA256=${SHA256}"
        TLS_VERIFY ON
        STATUS _status)
    list(GET _status 0 _result)
    if(NOT _result EQUAL 0)
        list(GET _status 1 _log)
        message(FATAL_ERROR "Download of ${_url} failed: ${_log}")
    endif()

    # Keep the patch independent of the upstream repository's line endings.
    file(READ "${_output}" _contents)
    string(REPLACE "\r\n" "\n" _contents "${_contents}")
    string(REGEX REPLACE "[ \t]+\n" "\n" _contents "${_contents}")
    file(WRITE "${_output}" "${_contents}")
endfunction()

file(REMOVE_RECURSE "${OUTPUT_DIRECTORY}")
file(MAKE_DIRECTORY "${OUTPUT_DIRECTORY}")

download_module("${_etsi_repository}" "${_etsi_revision}"
    EtsiTs103097Module.asn
    245a3c10c176497f658c6a4d9ec804d3226dda2ac10a4351e382ddb5afe9ff72)
download_module("${_etsi_repository}" "${_etsi_revision}"
    EtsiTs103097ExtensionModule.asn
    b94c9b373567dd9bfb15d61c8c206d5630f6b0c481ef41ddd574c96784a9eb1a)
download_module("${_ieee_repository}" "${_ieee_revision}"
    Ieee1609Dot2.asn
    82b5e35cbaadae1c6b2f087626b10d52afc73779c9ac6700c6445830d8824e0b)
download_module("${_ieee_repository}" "${_ieee_revision}"
    Ieee1609Dot2BaseTypes.asn
    bf2b3d66d394449319323f8a59d8084d963c3ad55d6790e1436ab897221690fe)

if(NOT EXISTS "${PATCH_FILE}")
    message(FATAL_ERROR "Missing SystemX PQC ASN.1 patch: ${PATCH_FILE}")
endif()
find_program(PATCH_EXECUTABLE patch)
if(NOT PATCH_EXECUTABLE)
    message(FATAL_ERROR "The patch utility is required to prepare the SystemX hybrid-PQC ASN.1 modules")
endif()
execute_process(
    COMMAND "${PATCH_EXECUTABLE}" --batch --forward -p1 -i "${PATCH_FILE}"
    WORKING_DIRECTORY "${OUTPUT_DIRECTORY}"
    RESULT_VARIABLE _patch_result)
if(NOT _patch_result EQUAL 0)
    message(FATAL_ERROR "Applying the SystemX hybrid-PQC ASN.1 patch failed")
endif()
