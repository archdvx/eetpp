CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
if(COMMAND cmake_policy)
    if(POLICY CMP0048)
        cmake_policy(SET CMP0048 OLD)
    endif(POLICY CMP0048)
endif(COMMAND cmake_policy)
project(eetpp)

set(EETPP_LIBS "")
set(EETPP_INCLUDE_DIRS "")

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
    return()
endif()

set(HAVE_OPENSSL FALSE)
find_package(OpenSSL)
if(OPENSSL_FOUND)
    if(WIN32)
        # On windows/mingw we need libeay32 too...
        find_library(LIB_EAY NAMES libeay32MD eay libeay libeay32)
        if(LIB_EAY)
            list(APPEND EETPP_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
            list(APPEND EETPP_LIBS ${OPENSSL_LIBRARIES} ${LIB_EAY})
            set(HAVE_OPENSSL TRUE)
        endif()
    else()
        list(APPEND EETPP_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
        list(APPEND EETPP_LIBS ${OPENSSL_LIBRARIES})
        set(HAVE_OPENSSL TRUE)
    endif()
else()
    message("OpenSSL library not found. Can't build eetpp")
    return()
endif()

set(HAVE_CURL FALSE)
find_package(CURL)
if(CURL_FOUND)
    list(APPEND EETPP_INCLUDE_DIRS ${CURL_INCLUDE_DIRS})
    list(APPEND EETPP_LIBS ${CURL_LIBRARIES})
    set(HAVE_CURL TRUE)
else()
    message("Curl library not found. Can't build eetpp")
    return()
endif()

include(CheckFunctionExists)
check_function_exists(vsnprintf HAVE_VSNPRINTF_EXISTS)
if(NOT HAVE_VSNPRINTF_EXISTS)
    check_function_exists(_vsnprintf HAVE_VSNPRINTF_EXISTS)
    if(NOT HAVE_VSNPRINTF_EXISTS)
        message("vsnprintf not found. Can't build eetpp")
        return()
    endif()
endif()

set(LIB_SUFFIX "" CACHE STRING "Define suffix of directory name (32/64)")

if(NOT WIN32)
# Source distribution
set(ARCHIVE_NAME libeetpp-1.00.0.tar.gz)
add_custom_target(dist COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && git archive --format tar.gz -o ${ARCHIVE_NAME} HEAD
)
endif(NOT WIN32)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libeetpp.pc.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/libeetpp.pc
               @ONLY )

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_BINARY_DIR})

set(eetpp_SRCS
    src/eet.cpp
)

set(eetpp_HEADERS
    src/templates.h
    src/eet.h
)

add_library(eetpp SHARED ${eetpp_SRCS})
set_target_properties(eetpp PROPERTIES
    VERSION 1.00.0
    SOVERSION 1.00
)
if(NOT WIN32)
    target_link_libraries(eetpp)
else(NOT WIN32)
    target_link_libraries(eetpp ${EETPP_LIBS})
endif(NOT WIN32)

# add a target to generate API documentation with Doxygen
find_package(Doxygen)
if(DOXYGEN_FOUND)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
add_custom_target(doc
${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
COMMENT "Generating API documentation with Doxygen" VERBATIM
)
endif(DOXYGEN_FOUND)

########### install files ###############
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libeetpp.pc
         DESTINATION ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/pkgconfig
         COMPONENT Devel)
install(TARGETS eetpp RUNTIME DESTINATION bin
                    LIBRARY DESTINATION lib${LIB_SUFFIX}
                    ARCHIVE DESTINATION lib${LIB_SUFFIX})
install(FILES ${eetpp_HEADERS} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/eetpp)
