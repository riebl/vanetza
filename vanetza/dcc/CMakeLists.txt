set(CXX_SOURCES
    burst_budget.cpp
    channel_load.cpp
    channel_load_smoothing.cpp
    regular_budget.cpp
    scheduler.cpp
    state_machine.cpp
)

vanetza_module(dcc ${CXX_SOURCES})

add_subdirectory(tests)

