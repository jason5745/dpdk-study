cmake_minimum_required(VERSION 3.0.0)
project(dpdk VERSION 0.1.0)

INCLUDE(FindPkgConfig) 
pkg_check_modules(PKGS_DEP REQUIRED 
    libdpdk
)

foreach(flag ${PKGS_DEP_CFLAGS}) 
	set(EXTRA_CFLGAS "${EXTRA_CFLGAS} ${flag}") 
endforeach(flag)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLGAS} -lpthread") 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_CFLGAS}") 

file(GLOB SOURCES
    lwip/unix/port/*.c
    lwip/api/*.c
    lwip/core/*.c
    lwip/core/ipv4/*.c
    lwip/core/ipv6/*.c
    lwip/netif/ppp/polarssl/*.c
    lwip/netif/ppp/*.c
    lwip/netif/*.c
    dpdk_lwip.c
)

add_executable(dpdk  ${SOURCES})
target_link_libraries(dpdk ${PKGS_DEP_LDFLAGS})

target_include_directories(dpdk
    PRIVATE 
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/lwip/include
        ${PROJECT_SOURCE_DIR}/lwip/unix/port/include
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
