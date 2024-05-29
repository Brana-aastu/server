
cmake_minimum_required(VERSION 3.15)
project(brana)

set(CMAKE_CXX_STANDARD 11)

include_directories(/usr/local/include/mysql_connector/include/jdbc boost_1_85_0 crow/include ${PROJECT_SOURCE_DIR}/include)

link_directories(/usr/local/include/mysql_connector/lib64)

#####

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

#####

add_executable(brana main.cpp)

target_link_libraries(brana mysqlcppconn)

#####

target_link_libraries(brana OpenSSL::SSL OpenSSL::Crypto)

#####


