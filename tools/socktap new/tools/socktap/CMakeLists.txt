find_package(Boost COMPONENTS system REQUIRED)
find_package(Threads REQUIRED)

add_executable(socktap
    application.cpp
    ethernet_device.cpp
    hello_application.cpp
    main.cpp
    router_context.cpp
    time_trigger.cpp
    CGpsData.cpp
    NetworkInterface.cpp
)
target_link_libraries(socktap gps)
target_include_directories(socktap PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(socktap ${Boost_SYSTEM_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} geonet btp net)
