include(UseGTest)
set(VANETZA_MODULE_TEST dcc)

add_gtest(BurstBudget burst_budget.cpp)
add_gtest(ChannelLoad channel_load.cpp)
add_gtest(ChannelLoadSmoothing channel_load_smoothing.cpp)
add_gtest(StateMachine state_machine.cpp)

