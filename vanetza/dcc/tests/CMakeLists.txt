include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES dcc)

add_gtest(BurstBudget burst_budget.cpp)
add_gtest(ChannelLoad channel_load.cpp)
add_gtest(ChannelLoadSmoothing channel_load_smoothing.cpp)
add_gtest(FlowControl flow_control.cpp)
add_gtest(FullyMeshedStateMachine fully_meshed_state_machine.cpp)
add_gtest(GradualStateMachine gradual_state_machine.cpp)
add_gtest(Mapping mapping.cpp)
add_gtest(StateMachineBudget state_machine_budget.cpp)
add_gtest(Scheduler scheduler.cpp)

