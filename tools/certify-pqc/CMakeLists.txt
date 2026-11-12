if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of certify-pqc because Boost::program_options is unavailable")
    return()
endif()

if(NOT VANETZA_WITH_OPENSSL AND NOT VANETZA_WITH_PSA)
    message(STATUS "Skip build of certify-pqc because no crypto provider and security module are available")
    return()
endif()

add_executable(certify-pqc
    certificate_builder.cpp
    files.cpp
    main.cpp
)
target_include_directories(certify-pqc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(certify-pqc PRIVATE Boost::program_options vanetza)
install(TARGETS certify-pqc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTS)
    add_test(NAME CertifyPqcWorkflow
        COMMAND ${CMAKE_COMMAND}
            -DCERTIFY_PQC=$<TARGET_FILE:certify-pqc>
            -DWORK_DIRECTORY=${PROJECT_BINARY_DIR}/tests/certify-pqc-workflow
            -P ${CMAKE_CURRENT_SOURCE_DIR}/test_workflow.cmake)
endif()
