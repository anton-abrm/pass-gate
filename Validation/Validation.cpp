#include "Validation.h"

bool Validation::is_formatted_guid(QString value)
{
    if (value.size() != 36)
        return false;

    QString::size_type hyphen_count = 0;

    for (QString::size_type i = 0; i < value.size(); ++i)
    {
        const auto ch = value.at(i);

        if (ch >= 'a' && ch <= 'f' ||
            ch >= 'A' && ch <= 'F' ||
            ch >= '0' && ch <= '9' )
            continue;

        if (ch == '-')
        {
            switch (i) {
                case 8:
                case 13:
                case 18:
                case 23:
                    hyphen_count++;
                    continue;
            }
        }

        return false;
    }

    if (hyphen_count != 4)
        return false;

    return true;
}