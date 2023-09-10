#include <vector>

#include "gtest/gtest.h"
#include "Crypto/SLIP39.h"

TEST(SLIP39, encrypt_master_secret) {

    Base::ZBytes plain = {1,2,3,4};

    Base::ZBytes expected = {0xd2, 0x30, 0x5b, 0xa6};

    Base::ZBytes cipher = SLIP39::encrypt_master_secret(plain, 0, {}, {});

    EXPECT_EQ(cipher, expected);

}

TEST(SLIP39, decrypt_master_secret) {

    Base::ZBytes cipher = {0xd2, 0x30, 0x5b, 0xa6};

    Base::ZBytes expected = {1, 2, 3, 4};

    Base::ZBytes plain = SLIP39::decrypt_master_secret(cipher, 0, {}, {});

    EXPECT_EQ(plain, expected);

}

TEST(SLIP39, encrypt_decrypt_master_secret) {

    Base::ZBytes plain = {1,2,3,4};

    Base::ZBytes cipher = SLIP39::encrypt_master_secret(plain, 0, {}, {});

    Base::ZBytes result = SLIP39::decrypt_master_secret(cipher, 0, {}, {});

    EXPECT_EQ(result, plain);

}