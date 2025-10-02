cmake_minimum_required(VERSION 3.10)
project(packetVisualizer)

set(CMAKE_CXX_STANDARD 23)

find_package(PkgConfig REQUIRED)

# Find libtins and libpcap
pkg_check_modules(TINS REQUIRED libtins)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${TINS_INCLUDE_DIRS} ${PCAP_INCLUDE_DIRS})
link_directories(${TINS_LIBRARY_DIRS} ${PCAP_LIBRARY_DIRS})

add_executable(main src/main.cpp)
target_link_libraries(main ${TINS_LIBRARIES} ${PCAP_LIBRARIES})

