cmake_minimum_required(VERSION 3.15)
project (loginSign)
# https://blog.csdn.net/afei__/article/details/81201039

include_directories(${PROJECT_NAME} ${PROJECT_SOURCE_DIR}/openssl-1.1.1/include) # OPENSSL的Include
include_directories(${PROJECT_NAME} ${PROJECT_SOURCE_DIR}/src) # 项目的Include

set(OPENSSL_HOME ${PROJECT_SOURCE_DIR}/openssl-1.1.1)
set(OPENSSL_LIBRARY_SSL ${OPENSSL_HOME}/lib/libssl.lib) # OPENSSL的lib
set(OPENSSL_LIBRARY_CRYPTO ${OPENSSL_HOME}/lib/libcrypto.lib) # OPENSSL的lib
set(OPENSSL_APPLINK ${PROJECT_SOURCE_DIR}/openssl-1.1.1/include/openssl/applink.c) # OPENSSL的applink.c

file(COPY ${OPENSSL_HOME}/bin/libcrypto-1_1-x64.dll DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/build)
file(COPY ${OPENSSL_HOME}/bin/libssl-1_1-x64.dll DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/build)

# 主程序
file(GLOB_RECURSE ALLCPP ${PROJECT_SOURCE_DIR}/src/*.cpp)
add_executable(${PROJECT_NAME} ${ALLCPP} ${OPENSSL_APPLINK} src/version.rc)

# 素材
file(COPY ${PROJECT_SOURCE_DIR}/src/resources DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/build)

# lib库连接
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARY_SSL})
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARY_CRYPTO})