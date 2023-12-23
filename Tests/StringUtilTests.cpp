#include "gtest/gtest.h"
#include "Base/StringUtil.h"



TEST(StringUtil, split) {

    const std::string s = "1,22,333";

    std::vector<std::string_view> expected;

    expected.emplace_back(&s[0], 1);
    expected.emplace_back(&s[2], 2);
    expected.emplace_back(&s[5], 3);

    const auto result = Base::StringUtil::split(s, ',');

    EXPECT_EQ(result, expected);
}



