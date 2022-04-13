set(CMAKE_SYSTEM_NAME "Linux")
set(CMAKE_SYSTEM_PROCESSOR "arm")
set(CMAKE_C_COMPILER "/opt/poky-craton2/2.6.2/sysroots/x86_64-pokysdk-linux/usr/bin/arm-poky-linux-gnueabi/arm-poky-linux-gnueabi-gcc")
set(CMAKE_CXX_COMPILER "/opt/poky-craton2/2.6.2/sysroots/x86_64-pokysdk-linux/usr/bin/arm-poky-linux-gnueabi/arm-poky-linux-gnueabi-g++")
set(CMAKE_C_FLAGS "--sysroot=/opt/poky-craton2/2.6.2/sysroots//cortexa7t2hf-neon-poky-linux-gnueabi -march=armv7ve -mthumb -mfpu=neon -mfloat-abi=hard -mcpu=cortex-a7" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "--sysroot=/opt/poky-craton2/2.6.2/sysroots//cortexa7t2hf-neon-poky-linux-gnueabi -I/opt/poky-craton2/2.6.2/sysroots//cortexa7t2hf-neon-poky-linux-gnueabi/usr/include  -march=armv7ve -mthumb -mfpu=neon -mfloat-abi=hard -mcpu=cortex-a7" CACHE STRING "" FORCE)
set(THREADS_PTHREAD_ARG "2" CACHE STRING "Forced by Autotalks toolchain" FORCE)
# Cache string needed in cmake v3.5.1, in v3.16.3 not anymore
# THREADS_PTHREAD_ARG needed for a bug that is also not present in v3.16.3 anymore

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(AUTOTALKS_CRATON true)

