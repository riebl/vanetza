set(CXX_SOURCES
    burst_budget.cpp
    bursty_transmit_rate_control.cpp
    channel_load.cpp
    flow_control.cpp
    fully_meshed_state_machine.cpp
    gradual_state_machine.cpp
    hooked_channel_probe_processor.cpp
    limeric.cpp
    limeric_budget.cpp
    limeric_transmit_rate_control.cpp
    mapping.cpp
    single_reactive_transmit_rate_control.cpp
    state_machine_budget.cpp
    smoothing_channel_probe_processor.cpp
    transmission.cpp
)

add_vanetza_component(dcc ${CXX_SOURCES})
target_link_libraries(dcc PUBLIC access net)

add_test_subdirectory(tests)

