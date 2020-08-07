cmake_minimum_required(VERSION 3.17)
project(FourInaRow)

set(CMAKE_CXX_STANDARD 14)

add_executable(FourInaRow main.cpp utility/NetMessage.cpp utility/NetMessage.h Logger.h Logger.cpp utility/Message.cpp utility/Message.h)