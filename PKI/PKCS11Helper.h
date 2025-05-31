#pragma once

#include <string>

#define CK_PTR *

#if _WIN32

    #define CK_DECLARE_FUNCTION(returnType, name) \
        returnType __declspec(dllimport) name

    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
        returnType __declspec(dllimport) (* name)

#else

    #define CK_DECLARE_FUNCTION(returnType, name) \
        returnType name

    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
        returnType (* name)

#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#if _WIN32
#pragma pack(push, cryptoki, 1)
#endif

#include "ThirdParty/PKCS11/published/3-00/pkcs11.h"

#if _WIN32
#pragma pack(pop, cryptoki)
#endif

namespace PKI {
    class PKCS11Helper final {
    public:
        static std::string get_message(CK_RV rv);
    };
}
