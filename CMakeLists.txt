cmake_minimum_required(VERSION 3.16)
project(DeepPacketAnalyzer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(PCAP libpcap)
endif()

if(NOT PCAP_FOUND)
    find_path(PCAP_INCLUDE_DIRS pcap.h PATHS /usr/include /usr/local/include /usr/include/pcap)
    find_library(PCAP_LIBRARIES pcap PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu /usr/lib64)
endif()

if(NOT PCAP_FOUND)
    message(FATAL_ERROR "libpcap not found. Install libpcap-dev or set PCAP_INCLUDE_DIRS and PCAP_LIBRARIES.")
endif()

add_executable(deep_packet_analyzer
    src/main.cpp
    src/capture/capture_manager.cpp
    src/capture/pcap_reader.cpp
    src/capture/pcap_writer.cpp
    src/parser/packet_parser.cpp
    src/parser/sni_extractor.cpp
    src/rules/rule_engine.cpp
    src/logger/logger.cpp
    src/detection/threat_detector.cpp
    src/dpi/dpi_engine.cpp
    src/dpi/types.cpp
)

target_include_directories(deep_packet_analyzer PRIVATE include)
target_compile_features(deep_packet_analyzer PRIVATE cxx_std_23)
target_link_libraries(deep_packet_analyzer PRIVATE ${PCAP_LIBRARIES} Threads::Threads)
