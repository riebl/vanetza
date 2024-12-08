find_package(Git REQUIRED)
if(NOT DIRECTORY)
    message(FATAL_ERROR "DIRECTORY variable is undefined")
endif()
file(MAKE_DIRECTORY "${DIRECTORY}")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2/-/raw/2022-published/Ieee1609Dot2.asn
    "${DIRECTORY}/IEEE1609dot2.asn")
file(READ "${DIRECTORY}/IEEE1609dot2.asn" _content)
string(REGEX REPLACE " Extension" " IeeeExtension" _content "${_content}")
file(WRITE "${DIRECTORY}/IEEE1609dot2.asn" "${_content}")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2/-/raw/2022-published/Ieee1609Dot2BaseTypes.asn
    "${DIRECTORY}/IEEE1609dot2BaseTypes.asn")
file(READ "${DIRECTORY}/IEEE1609dot2BaseTypes.asn" _content)
string(REGEX REPLACE "([\r\n])Extension" "\\1IeeeExtension" _content "${_content}")
file(WRITE "${DIRECTORY}/IEEE1609dot2BaseTypes.asn" "${_content}")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2/-/raw/2022-published/Ieee1609Dot2Crl.asn
    "${DIRECTORY}/IEEE1609dot2crl.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2/-/raw/2022-published/Ieee1609Dot2CrlBaseTypes.asn
    "${DIRECTORY}/IEEE1609dot2crlBaseTypes.asn")


file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1AcaEeInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1AcaEeInterface.asn")
file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1AcaLaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1AcaLaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1AcaMaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1AcaMaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1AcaRaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1AcaRaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1Acpc.asn
    "${DIRECTORY}/IEEE1609dot2dot1Acpc.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1CamRaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1CamRaInterface.asn")
file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1CertManagement.asn
    "${DIRECTORY}/IEEE1609dot2dot1CertManagement.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1EcaEeInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1EcaEeInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1EeMaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1EeMaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1EeRaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1EeRaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1LaMaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1LaMaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1LaRaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1LaRaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1MaRaInterface.asn
    "${DIRECTORY}/IEEE1609dot2dot1MaRaInterface.asn")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.1/-/raw/2022-published/Ieee1609Dot2Dot1Protocol.asn
    "${DIRECTORY}/IEEE1609dot2dot1Protocol.asn")
# --git-dir is needed as it will otherwise interface with the underlying vanetza git dir
execute_process(COMMAND "${GIT_EXECUTABLE}" --git-dir "${DIRECTORY}" -C "${DIRECTORY}" apply -v INPUT_FILE "patches/ieee/Ieeedot2dot1Protocol.patch" RESULT_VARIABLE PATCH_RESULT)
if(NOT PATCH_RESULT EQUAL 0)
        message(SEND_ERROR "Applying patch on IEEE1609dot2dot1Protocol failed!")
endif()