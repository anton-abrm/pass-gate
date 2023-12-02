#pragma once

#include <QString>

class SecretFormatter final {
public:

    static constexpr QChar c_password_separator = u'\u22c5';

    static QString convert_password_to_readable_form(QString password);
    static QString convert_password_to_original_from(QString password);

};



