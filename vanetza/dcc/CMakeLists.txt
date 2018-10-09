set(CXX_SOURCES
    burst_budget.cpp
    channel_load.cpp
    channel_load_smoothing.cpp
    flow_control.cpp
    fully_meshed_state_machine.cpp
    mapping.cpp
    regular_budget.cpp
    scheduler.cpp
)

add_vanetza_component(dcc ${CXX_SOURCES})
target_link_libraries(dcc PUBLIC net)

add_test_subdirectory(tests)

