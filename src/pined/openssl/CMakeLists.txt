cmake_minimum_required(VERSION 3.15...3.26)
project(${SKBUILD_PROJECT_NAME} LANGUAGES CXX)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)

if(DEFINED ENV{OPENSSL_USE_STATIC_LIBS})
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL REQUIRED)

pybind11_add_module(_openssl cxx/_openssl.cc)

target_compile_features(_openssl PRIVATE cxx_std_20)
target_link_libraries(_openssl PRIVATE OpenSSL::Crypto)
install(TARGETS _openssl LIBRARY DESTINATION .)
