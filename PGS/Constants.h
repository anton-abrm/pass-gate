#pragma once

namespace PGS {

    enum class SignatureVersion {
        SignatureV2 = 2,
    };

    enum class BIP39Version {
        BIP39V1 = 1,
        BIP39V2 = 2,
    };

    enum class EncryptionVersion {
        EncryptionV1 = 1,
        EncryptionV2 = 2,
    };

    enum class EntropySourceType {
        Signature,
        BIP39,
        Random,
    };

}