cmake_minimum_required(VERSION 3.10)

project(port-sharer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


find_package(Boost REQUIRED COMPONENTS system thread)

if (FLAG_OPENWRT)
    find_package(uci REQUIRED)
endif ()

file(GLOB_RECURSE APP_SOURCES "src/*.cpp")

include_directories(src)


add_executable(port-sharer ${APP_SOURCES})

target_include_directories(port-sharer
        PUBLIC
        ${Boost_INCLUDE_DIRS}
        ${UCI_INCLUDE_DIR}
)

target_link_libraries(port-sharer
        PUBLIC
        Boost::system
        Boost::thread
        ${UCI_LIBRARIES}
)


install(TARGETS port-sharer DESTINATION bin)

message(STATUS "Project name: ${PROJECT_NAME}")
message(STATUS "Boost libraries found: ${Boost_LIBRARIES}")
if (FLAG_OPENWRT)
    message(STATUS "UCI library found: ${UCI_LIBRARIES}")
    target_compile_definitions(port-sharer OPENWRT=1)
endif ()