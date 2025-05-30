cmake_minimum_required(VERSION 3.10)

project(pass-gate VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if (APPLE)
    list(APPEND CMAKE_PREFIX_PATH /opt/homebrew/opt/qt5)
    list(APPEND CMAKE_PREFIX_PATH /opt/homebrew/opt/openssl)
endif()

find_package(Qt5 COMPONENTS Core REQUIRED)
find_package(Qt5 COMPONENTS Widgets REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(pass-gate
        ${CMAKE_CURRENT_BINARY_DIR}/GitEnv.cpp
        Crypto/BIP39.cpp
        Base/Encoding.cpp
        Core/BIP39EntropySource.cpp
        Core/BIP39EntropySourceV2.cpp
        Core/EncryptionService.cpp
        Core/EncryptionServiceV1.cpp
        Core/EncryptionServiceV2.cpp
        Core/EntropySource.cpp
        Core/EntropySource.cpp
        Core/PKIProvider.cpp
        Core/PublicKeyInfo.cpp
        Core/RandomEntropySource.cpp
        Core/RandomNumberGenerator.cpp
        Core/SignatureEntropySourceV2.cpp
        Crypto/Crypto.cpp
        GUI/MainWindow.cpp
        GUI/MainWindow.ui
        GUI/PinDialog.cpp
        GUI/PinDialog.ui
        Keyboard/Keyboard.cpp
        Main.cpp
        PKI/PEMProvider.cpp
        PKI/PKCS11Provider.cpp
        PKI/PKCS12Provider.cpp
        PKI/PKIContainer.cpp
        PKI/HostRandomNumberGenerator.cpp
        Password/Password.cpp
        GUI/SecretFormatter.cpp
        Crypto/SLIP39.cpp
        Crypto/GF256.cpp
        Crypto/Shamir.cpp
        Core/BufferedRandomNumberGenerator.cpp
        Core/BufferedRandomNumberGenerator.h
        Core/MemoryRandomNumberGenerator.cpp
        PGS/V1/Package.cpp
        PGS/V1/EntropySourceInfo.cpp
        Base/StringUtil.cpp
        PGS/V1/SignatureEntropySourceInfo.cpp
        PGS/V1/BIP39EntropySourceInfo.cpp
        PGS/V1/RandomEntropySource.cpp
        PGS/V1/EncryptionInfo.cpp
        GUI/WidgetUtil.cpp
        PKI/PKCS11Helper.cpp
        PKI/PKCS11Helper.h
)

target_link_libraries(pass-gate
        Qt5::Core
        Qt5::Widgets
        OpenSSL::SSL
        )

if(LINUX)
    target_link_libraries(pass-gate xdo)
endif()

if(APPLE)

    set_target_properties(pass-gate PROPERTIES MACOSX_BUNDLE TRUE)

    # NOTE: Don't include the path in MACOSX_BUNDLE_ICON_FILE -- this is
    # the property added to Info.plist
    set(MACOSX_BUNDLE_ICON_FILE KeyChain)

    # And this part tells CMake where to find and install the file itself
    set(APP_ICON_MACOSX ${CMAKE_CURRENT_SOURCE_DIR}/KeyChain.icns)

    set_source_files_properties(${APP_ICON_MACOSX} PROPERTIES
            MACOSX_PACKAGE_LOCATION "Resources")

    target_sources(pass-gate PRIVATE ${APP_ICON_MACOSX})

    set_target_properties(pass-gate
            PROPERTIES OUTPUT_NAME "Pass Gate")

endif()

configure_file(Version.h.in Version.h @ONLY)

# Tests

add_subdirectory(ThirdParty/GoogleTest)

include_directories(
        ${gtest_SOURCE_DIR}/include
)

add_executable(pass-gate-tests
        Base/Encoding.cpp
        Core/RandomNumberGenerator.cpp
        Core/BufferedRandomNumberGenerator.cpp
        Core/MemoryRandomNumberGenerator.cpp
        Crypto/Crypto.cpp
        Crypto/SLIP39.cpp
        Crypto/GF256.cpp
        Crypto/Shamir.cpp
        Password/Password.cpp
        PGS/V1/Package.cpp
        PGS/V1/EntropySourceInfo.cpp
        PGS/V1/SignatureEntropySourceInfo.cpp
        PGS/V1/BIP39EntropySourceInfo.cpp
        Tests/EncodingTests.cpp
        Tests/SLIP39Tests.cpp
        Tests/GF256Tests.cpp
        Tests/ShamirTests.cpp
        Tests/BufferedRandomNumberGeneratorTests.cpp
        Tests/PasswordTests.cpp
        Tests/PGSV1Tests.cpp
        Base/StringUtil.cpp
        Tests/StringUtilTests.cpp
        PGS/V1/RandomEntropySource.cpp
        PGS/V1/EncryptionInfo.cpp
)

target_link_libraries(pass-gate-tests
        gtest
        gtest_main
        OpenSSL::SSL
        )

ADD_CUSTOM_COMMAND(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/GitEnv.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/Dummy.cpp
        COMMAND ${CMAKE_COMMAND} -P
        ${CMAKE_CURRENT_SOURCE_DIR}/GitEnv.cmake)
