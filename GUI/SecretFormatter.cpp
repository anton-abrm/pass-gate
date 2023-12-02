#include <QStringList>
#include "SecretFormatter.h"

static bool is_formatted_serial_number(const QString &value) {

    if (value.isEmpty() || value.front() == '-' || value.back() == '-')
        return false;

    QString::size_type separator_count = 0;
    QString::size_type last_separator = -1;

    for (QString::size_type i = 0; i < value.size(); ++i)
    {
        if (value[i] != '-')
            continue;

        if (i - last_separator < 2)
            return false;

        separator_count++;

        last_separator = i;
    }

    if (separator_count < 2)
        return false;

    return true;
}

QString SecretFormatter::convert_password_to_readable_form(QString password)
{
    if (password.size() == 0)
        return password;

    if (password.contains('\x20'))
        return password;

    if (is_formatted_serial_number(password))
        return password;

    QList<int> sizes = {4, 5, 6};

    for (auto size: sizes) {

        if (password.size() % size == 0) {

            QString formatted_secret;

            formatted_secret.reserve(password.size() + password.size() / size - 1);

            for (int i = 0; i < password.size(); ++i) {

                if (i != 0 && i % size == 0)
                    formatted_secret.append(c_password_separator);

                formatted_secret.append(password[i]);
            }

            return formatted_secret;
        }
    }

    return password;
}

QString SecretFormatter::convert_password_to_original_from(QString password)
{
    return password.remove(c_password_separator);
}
