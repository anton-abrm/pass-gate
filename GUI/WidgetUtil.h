#pragma once

#include <QComboBox>

namespace GUI {

    class WidgetUtil final {

    public:

        static void select_combo_box_item_with_data(QComboBox * combo_box, const QVariant &item_data);
        static void select_combo_box_item_starting_with(QComboBox * combo_box, const QString &text);

    };
}
