set(_its_asn1_source_file "asn1c_its_sources.txt")
set(_pki_asn1_source_file "asn1c_pki_sources.txt")
set(_sec_asn1_source_file "asn1c_security_sources.txt")
set(_support_asn1_source_file "asn1c_support_sources.txt")

set(_its_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/its")
set(_pki_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/pki")
set(_sec_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/security")
set(_support_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/support")

option(VANETZA_ASN1_WITH_ASN1C "Enable asn1c targets" OFF)
if(VANETZA_ASN1_WITH_ASN1C)
    find_package(ASN1C 0.9.29 REQUIRED MODULE)
    set(ASN1C_FLAGS "-fcompound-names -fincludes-quoted -no-gen-example" CACHE STRING "asn1c compiler options")
    mark_as_advanced(ASN1C_FLAGS)
    string(REPLACE " " ";" _asn1c_flags "${ASN1C_FLAGS}")

    set(_its_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/TS102894-2v131-CDD.asn
        ${PROJECT_SOURCE_DIR}/asn1/EN302637-2v141-CAM.asn
        ${PROJECT_SOURCE_DIR}/asn1/EN302637-3v131-DENM.asn
    )

    set(_its_asn1_files_depending_on_iso
        ${PROJECT_SOURCE_DIR}/asn1/TR103562v211-CPM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-MAPEM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-RTCMEM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-SPATEM.asn
    )

    option(VANETZA_ASN1_WITH_ISO "Fetch ISO ASN.1 files for a more complete ITS message set" OFF)
    if(VANETZA_ASN1_WITH_ISO)
        set(_iso_asn1_files ISO14816.asn ISO19091.asn ISO24534-3.asn)
        list(TRANSFORM _iso_asn1_files PREPEND ${PROJECT_BINARY_DIR}/iso/)
        add_custom_command(OUTPUT ${_iso_asn1_files}
            COMMAND ${CMAKE_COMMAND} -DDIRECTORY=${PROJECT_BINARY_DIR}/iso -P fetch_iso_asn1_files.cmake
            COMMENT "Fetch and patch ISO 19091 ASN.1 file"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            VERBATIM)

        set(_its_asn1_files ${_iso_asn1_files} ${_its_asn1_files} ${_its_asn1_files_depending_on_iso})
    endif()

    set(_pki_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-BaseTypes.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-MessagesCa.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TrustLists.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesAuthorization.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesAuthorizationValidation.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesCaManagement.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesEnrolment.asn
    )
    set(_sec_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/TS103097v131.asn
        ${PROJECT_SOURCE_DIR}/asn1/IEEE1609dot2.asn
        ${PROJECT_SOURCE_DIR}/asn1/IEEE1609dot2BaseTypes.asn
    )

    add_custom_command(OUTPUT ${_support_asn1_dir}
        DEPENDS "${ASN1C_SKELETON_DIR}"
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_support_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DDESTINATION=${_support_asn1_dir}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/copy_asn1c_skeleton.cmake
        COMMENT "Copying generic asn1c support code" VERBATIM
        WORKING_DIRECTORY ${ASN1C_SKELETON_DIR})
    add_custom_command(OUTPUT "${_support_asn1_source_file}"
        DEPENDS ${_support_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=support -DASN1C_SOURCE_FILE=${_support_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_command(OUTPUT ${_its_asn1_dir}
        DEPENDS ${_its_asn1_files}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_its_asn1_dir}
        COMMAND ${ASN1C_EXECUTABLE} ${_asn1c_flags} -R -D ${_its_asn1_dir} ${_its_asn1_files} test.asn
        COMMENT "Generating code from ITS application ASN.1 modules (CDD, CA, DEN)" VERBATIM
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_custom_command(OUTPUT "${_its_asn1_source_file}"
        DEPENDS ${_its_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=its -DASN1C_SOURCE_FILE=${_its_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_command(OUTPUT ${_pki_asn1_dir}
        DEPENDS ${_pki_asn1_files}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_pki_asn1_dir}
        COMMAND ${ASN1C_EXECUTABLE} ${_asn1c_flags} -R -D ${_pki_asn1_dir} ${_pki_asn1_files} ${_sec_asn1_files}
        COMMENT "Generating code from PKI (TS 102 941) ASN.1 modules" VERBATIM
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_custom_command(OUTPUT "${_pki_asn1_source_file}"
        DEPENDS ${_pki_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=pki -DASN1C_SOURCE_FILE=${_pki_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_command(OUTPUT "${_sec_asn1_dir}"
        DEPENDS ${_sec_asn1_files}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_sec_asn1_dir}
        COMMAND ${ASN1C_EXECUTABLE} ${_asn1c_flags} -R -D ${_sec_asn1_dir} ${_sec_asn1_files}
        COMMENT "Generating code from Security (1609.2 and TS 103 097) ASN.1 modules" VERBATIM)
    add_custom_command(OUTPUT "${_sec_asn1_source_file}"
        DEPENDS ${_sec_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=security -DASN1C_SOURCE_FILE=${_sec_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_target(generate_asn1c DEPENDS
        "${_support_asn1_dir}" "${_support_asn1_source_file}"
        "${_its_asn1_dir}" "${_its_asn1_source_file}"
        "${_pki_asn1_dir}" "${_pki_asn1_source_file}"
        "${_sec_asn1_dir}" "${_sec_asn1_source_file}"
        VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_skeleton.cmake
        COMMENT "Patching asn1c support files"
        WORKING_DIRECTORY ${_support_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated ITS application asn1c files"
        WORKING_DIRECTORY ${_its_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated PKI asn1c files"
        WORKING_DIRECTORY ${_pki_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated security asn1c files"
        WORKING_DIRECTORY ${_sec_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPATCH_DIRECTORY=${CMAKE_CURRENT_SOURCE_DIR}/patches
            -P ${CMAKE_CURRENT_SOURCE_DIR}/apply_patches.cmake
        COMMENT "Applying hot-fixes to generated asn1c files"
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} VERBATIM)
    if(VANETZA_ASN1_WITH_ISO)
        add_custom_command(TARGET generate_asn1c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -DPATCH_DIRECTORY=${CMAKE_CURRENT_SOURCE_DIR}/patches/iso
                -P ${CMAKE_CURRENT_SOURCE_DIR}/apply_patches.cmake
                COMMENT "Applying hot-fixes to generated asn1c ITS ISO files"
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} VERBATIM)
    endif()

    # wipe directory with generated files before generating
    add_custom_target(clean_asn1c
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_support_asn1_dir}
          -DASN1C_SOURCE_FILE=${_support_asn1_source_file}
          -P clean_asn1c.cmake
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_its_asn1_dir}
          -DASN1C_SOURCE_FILE=${_its_asn1_source_file}
          -P clean_asn1c.cmake
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_pki_asn1_dir}
          -DASN1C_SOURCE_FILE=${_pki_asn1_source_file}
          -P clean_asn1c.cmake
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_sec_asn1_dir}
          -DASN1C_SOURCE_FILE=${_sec_asn1_source_file}
          -P clean_asn1c.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)
    add_dependencies(generate_asn1c clean_asn1c)
endif()

function(add_asn1_component NAME)
    set(_source_file "asn1c_${NAME}_sources.txt")
    file(STRINGS "${_source_file}" _sources REGEX "^[^#]+")
    if (NOT _sources)
        message(AUTHOR_WARNING "source file ${_source_file} is empty, fix this now!")
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/asn1_${NAME}_no_sources.c
            "#error \"generated ${NAME} ASN.1 source files are missing\"")
        set(_sources ${CMAKE_CURRENT_BINARY_DIR}/asn1_${NAME}_no_sources.c)
    endif()
    add_vanetza_component(asn1_${NAME} ${_sources})
    set_target_properties(asn1_${NAME} PROPERTIES C_STANDARD 11)

    if ("${NAME}" STREQUAL "support")
        target_include_directories(asn1_support PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/support>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/vanetza/asn1/support>)
    else()
        target_link_libraries(asn1_${NAME} PUBLIC asn1_support)
    endif()

    # Silence warnings in code generated by asn1c
    if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        set_property(SOURCE ${_sources} APPEND PROPERTY COMPILE_OPTIONS "-Wno-parentheses-equality")
    endif()

    if(VANETZA_INSTALL)
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${NAME}
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vanetza/asn1
            FILES_MATCHING PATTERN "*.h")
    endif()
endfunction()

add_asn1_component(support)
add_asn1_component(its)
add_asn1_component(security)
add_asn1_component(pki)

add_vanetza_component(asn1 asn1c_wrapper.cpp)
target_link_libraries(asn1 PUBLIC asn1_its Boost::boost)

add_test_subdirectory(tests)
