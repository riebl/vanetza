# Install script for directory: /home/sachin/projects/Socktap_KDevelop/vanetza

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/asn1/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/btp/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/common/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/dcc/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/facilities/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/geonet/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/gnss/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/net/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/security/cmake_install.cmake")
  include("/home/sachin/projects/Socktap_KDevelop/build/vanetza/units/cmake_install.cmake")

endif()

