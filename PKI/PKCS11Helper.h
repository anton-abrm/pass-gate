#pragma once

#include <string>

#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "ThirdParty/PKCS11/published/3-00/pkcs11.h"

namespace PKI {
    class PKCS11Helper final {
    public:
        static std::string get_message(CK_RV rv);
    };
}
