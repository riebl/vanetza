add_executable(fuzzing-persistent persistent.cpp)
target_link_libraries(fuzzing-persistent PUBLIC vanetza)

add_executable(fuzzing-run run.cpp)
target_link_libraries(fuzzing-run PUBLIC vanetza)
