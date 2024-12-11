cmake_minimum_required(VERSION 3.15)
project(zmq_ex)

# Исходные файлы проекта
set(SERVER_SOURCES
    tests/server.c
)

set(CLIENT_SOURCES
    tests/client.c
)

set(HEADERS
    include/header.h
)

# Найти библиотеку PCAP через pkg-config
find_library(PCAP_LIBRARY pcap) 
find_path(PCAP_INCLUDE_DIR pcap.h)

# Библиотека zmq
find_library(LIBZMQ_LIBRARY zmq)
find_path(LIBZMQ_INCLUDE_DIR zmq.h) 

# Библиотека czmq 
find_library(CZMQ_LIBRARY czmq)
find_path(CZMQ_INCLUDE_DIR czmq.h)

# Путь до необходимых библиотек
include_directories(${PATH}/libzmq)
link_directories(${PATH}/libzmq)

include_directories(${PATH}/czmq)
link_directories(${PATH}/czmq)

# Добавление исполняемых файлов
add_executable(server ${SERVER_SOURCES})
add_executable(client ${CLIENT_SOURCES})

# Линковка с библиотеками libzmq и czmq 
target_link_libraries(server ${LIBZMQ_LIBRARY} ${CZMQ_LIBRARY})
target_link_libraries(client ${LIBZMQ_LIBRARY} ${CZMQ_LIBRARY})
target_link_libraries(server ${LIBZMQ_LIBRARY} ${PCAP_LIBRARY})