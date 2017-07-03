cmake_minimum_required(VERSION 3.5)
project(ipv6_modbus_opcua_server_dongda)

set(CMAKE_C_STANDARD 99)


set(SOURCE_FILES src/ipv6_modbus_opcua_server.c src/get_config.c src/get_config.h src/modbus_data.h
                 src/open62541.c src/open62541.h src/socket.c src/socket.h)

add_executable(ipv6_modbus_opcua_server_dongda ${SOURCE_FILES})

target_link_libraries(ipv6_modbus_opcua_server_dongda modbus pthread)