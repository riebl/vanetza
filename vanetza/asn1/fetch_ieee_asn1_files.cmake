if(NOT OUTPUT_DIRECTORY)
    message(FATAL_ERROR "OUTPUT_DIRECTORY variable is undefined")
endif()
file(MAKE_DIRECTORY "${OUTPUT_DIRECTORY}")
if(NOT PATCH_DIRECTORY)
    message(FATAL_ERROR "PATH_DIRECTORY variable is undefined")
endif()

macro(download URL OUTPUT_FILE)
    file(DOWNLOAD "${URL}" "${OUTPUT_FILE}"
        STATUS _status)
    list(GET _status 0 _result)
    if(NOT _result EQUAL 0)
        list(GET _status 1 _log)
        message(FATAL_ERROR "Download of ${URL} failed: ${_log}")
    endif()
endmacro()

macro(download_ieee1609dot2 ASN1_FILE)
    download(
        "https://forge.etsi.org/rep/ITS/asn1/ieee1609.2/-/raw/2022-published/${ASN1_FILE}"
        "${OUTPUT_DIRECTORY}/${ASN1_FILE}")
endmacro()

macro(download_ieee1609dot2dot1 ASN1_FILE)
    download(
        "https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/${ASN1_FILE}"
        "${OUTPUT_DIRECTORY}/${ASN1_FILE}")
endmacro()

download_ieee1609dot2("Ieee1609Dot2.asn")
download_ieee1609dot2("Ieee1609Dot2BaseTypes.asn")
download_ieee1609dot2("Ieee1609Dot2Crl.asn")
download_ieee1609dot2("Ieee1609Dot2CrlBaseTypes.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1AcaEeInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1AcaLaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1AcaMaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1AcaRaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1Acpc.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1CamRaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1CertManagement.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1EcaEeInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1EeMaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1EeRaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1LaMaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1LaRaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1MaRaInterface.asn")
download_ieee1609dot2dot1("Ieee1609Dot2Dot1Protocol.asn")

file(READ "${OUTPUT_DIRECTORY}/Ieee1609Dot2.asn" _content)
string(REGEX REPLACE " Extension" " IeeeExtension" _content "${_content}")
file(WRITE "${OUTPUT_DIRECTORY}/Ieee1609Dot2.asn" "${_content}")

file(READ "${OUTPUT_DIRECTORY}/Ieee1609Dot2BaseTypes.asn" _content)
string(REGEX REPLACE "([\r\n])Extension" "\\1IeeeExtension" _content "${_content}")
file(WRITE "${OUTPUT_DIRECTORY}/Ieee1609Dot2BaseTypes.asn" "${_content}")

execute_process(COMMAND patch -p1 -i "${PATCH_DIRECTORY}/scoped-certificate-request.patch"
    WORKING_DIRECTORY "${OUTPUT_DIRECTORY}"
    RESULT_VARIABLE PATCH_RESULT)
if(NOT PATCH_RESULT EQUAL 0)
    message(SEND_ERROR "Applying patch on IEEE 1609.2.1 ScopedCertificateRequest failed!")
endif()
