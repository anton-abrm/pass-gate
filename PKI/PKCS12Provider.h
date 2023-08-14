#pragma once

#include "PKIContainer.h"

namespace PKI {

class PKCS12Provider final : virtual public PKI::PKIContainer
{

private:
    PKCS12Provider();

public:

    static std::shared_ptr<PKCS12Provider> instance();

    void initialize(std::string_view provider) override;
};
}


