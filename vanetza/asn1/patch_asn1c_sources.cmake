# remove generated makefile
file(REMOVE Makefile.am.libasncodec)

file(GLOB _files *.c *.h)
foreach(_file ${_files})
    set(_patched "")
    file(READ "${_file}" _content)

    # change #include brackets to quotes in asn1c support code
    string(REGEX MATCHALL "#include <[^>]+>" _matches "${_content}")
    foreach(_match IN LISTS _matches)
        string(REGEX MATCH "^#include <([^>]+)>" _ignored "${_match}")
        set(_header "${CMAKE_MATCH_1}")
        if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_header}")
            string(REPLACE "#include <${_header}>" "#include \"${_header}\"" _content "${_content}")
            list(APPEND _patched "include")
        endif()
    endforeach()

    # remove absolute paths from generated files
    string(REGEX REPLACE "`asn1c (.*) -D [^`]+`" "`asn1c \\1`" _content "${_content}")
    if (CMAKE_MATCH_1)
        list(APPEND _patched "abspath")
    endif()

    if(_patched)
        file(WRITE "${_file}" "${_content}")
        message(STATUS "patched ${_file} (${_patched})")
    endif()
endforeach()

## those fixes are for Windows builds using MSVC
# add inclusion of inttypes.h
file(READ OBJECT_IDENTIFIER.c _content)
string(REPLACE "#include <limits.h>"
    "#include <inttypes.h> /* for PRIu32 */\n#include <limits.h>"
    _content "${_content}")
file(WRITE OBJECT_IDENTIFIER.c "${_content}")
# random() is a POSIX function
file(READ asn_random_fill.c _content)
string(REPLACE "random()" "rand()" _content "${_content}")
file(WRITE asn_random_fill.c "${_content}")
# remove #define for some math functions
file(READ asn_system.h _content)
string(REPLACE "#define isnan _isnan\n" "" _content "${_content}")
string(REPLACE "#define finite _finite\n" "" _content "${_content}")
string(REPLACE "#define copysign _copysign\n" "" _content "${_content}")
string(REPLACE "#define	ilogb	_logb\n" "" _content "${_content}")
file(WRITE asn_system.h "${_content}")
message(STATUS "applied MSVC compatibility changes")
