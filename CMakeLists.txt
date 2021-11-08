cmake_minimum_required(VERSION 3.10)

project(shadow-gate VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt5 COMPONENTS Core REQUIRED)
find_package(Qt5 COMPONENTS Widgets REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(pass-gate
        Main.cpp
        GUI/MainWindow.cpp
        GUI/MainWindow.ui
        GUI/PinDialog.cpp
        GUI/PinDialog.ui
        Password/Password.cpp
        PKCS11/PKCS11.cpp
        Keyboard/Keyboard.cpp
        Convert/Convert.cpp PKCS11/RSACertificate.cpp PKCS11/RSACertificate.h)

target_link_libraries(pass-gate
        Qt5::Core
        Qt5::Widgets
        OpenSSL::SSL
        pkcs11-helper
        xdo)
