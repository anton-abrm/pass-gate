#pragma once

#include <QString>

class Validation final {
public:
    static bool is_formatted_guid(QString value);
};