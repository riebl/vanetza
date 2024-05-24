add_executable(fuzzing-persistent router_fuzzing_context.cpp persistent.cpp)
target_link_libraries(fuzzing-persistent PUBLIC vanetza)

add_executable(fuzzing-run router_fuzzing_context.cpp  run.cpp)
target_link_libraries(fuzzing-run PUBLIC vanetza)
