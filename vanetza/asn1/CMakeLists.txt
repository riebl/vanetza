set(_its_asn1_source_file "asn1c_its_sources.txt")
set(_sec_asn1_source_file "asn1c_security_sources.txt")
set(_support_asn1_source_file "asn1c_support_sources.txt")

set(_its_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/its")
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
        ${PROJECT_SOURCE_DIR}/asn1/ISO_TS_19091_CPM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TR103562v211.asn
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
        COMMENT "Patching generated security asn1c files"
        WORKING_DIRECTORY ${_sec_asn1_dir} VERBATIM)

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
          -DASN1C_OUTPUT_DIR=${_sec_asn1_dir}
          -DASN1C_SOURCE_FILE=${_sec_asn1_source_file}
          -P clean_asn1c.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)
    add_dependencies(generate_asn1c clean_asn1c)
endif()


set(CXX_SOURCES asn1c_wrapper.cpp)
file(STRINGS "${_its_asn1_source_file}" ITS_ASN1C_SOURCES REGEX "^[^#]+")
file(STRINGS "${_support_asn1_source_file}" SUPPORT_ASN1C_SOURCES REGEX "^[^#]+")

add_vanetza_component(asn1 ${CXX_SOURCES} ${ITS_ASN1C_SOURCES} ${SUPPORT_ASN1C_SOURCES})
target_include_directories(asn1 PUBLIC
    $<BUILD_INTERFACE:${_support_asn1_dir}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/vanetza/asn1/support>)
target_link_libraries(asn1 PUBLIC Boost::boost)
set_target_properties(asn1 PROPERTIES C_STANDARD 11)

if(VANETZA_INSTALL)
    install(DIRECTORY ${_support_asn1_dir} ${_its_asn1_dir} ${_sec_asn1_dir}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vanetza/asn1
        FILES_MATCHING PATTERN "*.h")
endif()


file(STRINGS "${_sec_asn1_source_file}" SEC_ASN1C_SOURCES REGEX "^[^#]+")
if (SEC_ASN1C_SOURCES)
    add_library(asn1_security STATIC ${SEC_ASN1C_SOURCES})
    target_include_directories(asn1_security PUBLIC
        $<BUILD_INTERFACE:${_support_asn1_dir}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/vanetza/asn1/support>)
    set_target_properties(asn1_security PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 11)
else()
    message(AUTHOR_WARNING "source file ${_sec_asn1_source_file} is empty, fix this now!")
endif()


# Silence warnings in code generated by asn1c
if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set_property(SOURCE ${SUPPORT_ASN1C_SOURCES} ${ITS_ASN1C_SOURCES} ${SEC_ASN1C_SOURCES}
        APPEND PROPERTY COMPILE_OPTIONS "-Wno-parentheses-equality")
endif()

add_test_subdirectory(tests)

