find_package(Boost COMPONENTS date_time REQUIRED)

set(CXX_SOURCES
    path_history.cpp
    path_point.cpp
)

vanetza_module(facilities ${CXX_SOURCES})
vanetza_module_property(facilities INCLUDE_DIRECTORIES
    ${Boost_INCLUDE_DIRS}
)
vanetza_module_dependencies(facilities
    ${Boost_DATE_TIME_LIBRARY}
)

add_subdirectory(tests)

