macro(add_asn1c DIR TARGET)
    file(GLOB _sources ${DIR}/*.c)
    list(REMOVE_ITEM _sources ${DIR}/converter-sample.c)
    if(NOT _sources)
        message(FATAL_ERROR "Generate sources from ASN.1 specification in ${DIR} using asn1c at first!")
    endif()

    add_library(${TARGET} STATIC ${_sources})
    set_target_properties(${TARGET} PROPERTIES
        INCLUDE_DIRECTORIES ${DIR}
        INTERFACE_INCLUDE_DIRECTORIES ${DIR}
        COMPILE_FLAGS -fPIC)
endmacro()
