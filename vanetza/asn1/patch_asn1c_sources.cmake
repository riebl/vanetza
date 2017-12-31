# remove superfluous example code
file(REMOVE converter-example.c converter-example.mk)

# remove generated makefiles
file(GLOB _files Makefile.am.*)
if(_files)
    file(REMOVE ${_files})
endif()

# change #include brackets to quotes in asn1c support code
file(GLOB _files *.c *.h)
foreach(_file ${_files})
    set(_patched FALSE)
    file(READ "${_file}" _content)
    string(REGEX MATCHALL "#include <[^>]+>" _matches "${_content}")
    foreach(_match IN LISTS _matches)
        string(REGEX MATCH "^#include <([^>]+)>" _ignored "${_match}")
        set(_header "${CMAKE_MATCH_1}")
        if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_header}")
            string(REPLACE "#include <${_header}>" "#include \"${_header}\"" _content "${_content}")
            set(_patched TRUE)
        endif()
    endforeach()

    if(_patched)
        file(WRITE "${_file}" "${_content}")
        message(STATUS "patched #include in ${_file}")
    endif()
endforeach()

