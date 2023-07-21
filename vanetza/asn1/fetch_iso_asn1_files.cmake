if(NOT DIRECTORY)
    message(FATAL_ERROR "DIRECTORY variable is undefined")
endif()
file(MAKE_DIRECTORY "${DIRECTORY}")

file(DOWNLOAD
    https://standards.iso.org/iso/14816/ISO14816%20ASN.1%20repository/ISO14816_AVIAEINumberingAndDataStructures.asn
    "${DIRECTORY}/ISO14816.asn")
file(READ "${DIRECTORY}/ISO14816.asn" _content)
string(REPLACE "IssuerIdentifier" "IssuerIdentifierIso" _content "${_content}")
file(WRITE "${DIRECTORY}/ISO14816.asn" "${_content}")

file(DOWNLOAD
    https://forge.etsi.org/rep/ITS/asn1/is_ts103301/-/raw/v2.1.1/iso-patched/ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn
    "${DIRECTORY}/ISO24534-3.asn")

file(DOWNLOAD
    https://standards.iso.org/iso/ts/19091/ed-2/en/ISO-TS-19091-addgrp-C-2018.asn
    "${DIRECTORY}/ISO19091.asn")
file(READ "${DIRECTORY}/ISO19091.asn" _content)
string(REPLACE "HeadingConfidence" "HeadingConfidenceIso" _content "${_content}")
string(REPLACE "Heading" "HeadingIso" _content "${_content}")
string(REPLACE "SpeedConfidence" "SpeedConfidenceIso" _content "${_content}")
file(WRITE "${DIRECTORY}/ISO19091.asn" "${_content}")

file(DOWNLOAD
    https://standards.iso.org/iso/ts/19321/ed-2/en/ISO19321IVIv2.asn
    "${DIRECTORY}/ISO19321.asn")

file(DOWNLOAD
    "https://forge.etsi.org/rep/ITS/asn1/is_ts103301/-/raw/v2.1.1/iso-patched/ISO14906(2018)EfcDsrcGenericv7-patched.asn"
    "${DIRECTORY}/ISO14906-1-7.asn")
file(READ "${DIRECTORY}/ISO14906-1-7.asn" _content)
string(REPLACE "IssuerIdentifier" "IssuerIdentifierIso" _content "${_content}")
file(WRITE "${DIRECTORY}/ISO14906-1-7.asn" "${_content}")

file(DOWNLOAD
    "https://forge.etsi.org/rep/ITS/asn1/is_ts103301/-/raw/v2.1.1/iso-patched/ISO14906(2018)EfcDsrcApplicationv6-patched.asn"
    "${DIRECTORY}/ISO14906-0-6.asn")
file(READ "${DIRECTORY}/ISO14906-0-6.asn" _content)
string(REPLACE "StationType" "StationTypeIso" _content "${_content}")
string(REPLACE "IssuerIdentifier" "IssuerIdentifierIso" _content "${_content}")
file(WRITE "${DIRECTORY}/ISO14906-0-6.asn" "${_content}")

file(DOWNLOAD
    "https://forge.etsi.org/rep/ITS/asn1/is_ts103301/-/raw/v2.1.1/iso-patched/ISO14823-missing.asn"
    "${DIRECTORY}/ISO14823.asn")

file(DOWNLOAD
    "https://forge.etsi.org/rep/LIBS/LibIts/-/raw/798bfce82f199cdfdef4289098bf900832e3932c/asn1/IS/IVI_ISO_TS_17419.asn"
    "${DIRECTORY}/ISO17419.asn")
