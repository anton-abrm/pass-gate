#pragma once

#include "PKIContainer.h"

namespace PKI {

class PEMProvider final : virtual public PKI::PKIContainer
{

private:
    PEMProvider();

    static int password_callback(char *buffer, int size, int rwflag, void *u);

public:

    static std::shared_ptr<PEMProvider> instance();

    void initialize(std::string_view provider) override;
};
}


