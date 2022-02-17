cmake_minimum_required(VERSION 3.0.0)
project(dpdk VERSION 0.1.0)

INCLUDE(FindPkgConfig) 
pkg_check_modules(PKGS_DEP REQUIRED 
    libdpdk
)

foreach(flag ${PKGS_DEP_CFLAGS}) 
	set(EXTRA_CFLGAS "${EXTRA_CFLGAS} ${flag}") 
endforeach(flag)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLGAS} -lpthread -g") 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_CFLGAS}") 

file(GLOB SOURCES
    lwip/contrib/ports/unix/port/*.c
    lwip/src/api/*.c
    lwip/src/core/*.c
    lwip/src/core/ipv4/*.c
    lwip/src/core/ipv6/*.c
    lwip/src/netif/ethernet.c
    lwip/contrib/apps/httpserver/httpserver-netconn.c
    lwip/contrib/apps/tcpecho/tcpecho.c
    /root/dpdk-study/lwip/src/apps/mqtt/mqtt.c
    paho.mqtt.c/src/*.c
    mqtt_example.c
    dpdk_lwip.c
    dpdkif.c
)

add_executable(dpdk  ${SOURCES})
target_link_libraries(dpdk ${PKGS_DEP_LDFLAGS})

target_include_directories(dpdk
    PRIVATE 
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/lwip/src/include
        ${PROJECT_SOURCE_DIR}/lwip/contrib/ports/unix/port/include
        ${PROJECT_SOURCE_DIR}/lwip/contrib/apps/httpserver
        ${PROJECT_SOURCE_DIR}/paho.mqtt.c/src
        ${PROJECT_SOURCE_DIR}/lwip/contrib/apps/tcpecho
        
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
