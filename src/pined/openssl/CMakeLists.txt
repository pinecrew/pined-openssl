cmake_minimum_required(VERSION 3.15...3.26)
project(${SKBUILD_PROJECT_NAME} LANGUAGES CXX)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

pybind11_add_module(native native.cc)

target_compile_features(native PRIVATE cxx_std_20)
target_link_libraries(native PRIVATE OpenSSL::Crypto)
install(TARGETS native LIBRARY DESTINATION .)
