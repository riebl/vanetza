add_executable(reference-vector-codec vector_codec_main.cpp)
target_link_libraries(reference-vector-codec PRIVATE asn1)

if(BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME ReferenceVectorReplay
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/replay.py
                ${PROJECT_SOURCE_DIR}/vanetza/asn1/tests/reference_vectors/intersection_01
                --codec $<TARGET_FILE:reference-vector-codec>)
    endif()
endif()
