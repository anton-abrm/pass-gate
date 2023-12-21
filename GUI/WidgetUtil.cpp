#include "WidgetUtil.h"

void GUI::WidgetUtil::select_combo_box_item_with_data(QComboBox * combo_box, const QVariant &item_data) {
    for (int i = 0; i < combo_box->count(); ++i) {
        if (item_data == combo_box->itemData(i)) {
            combo_box->setCurrentIndex(i);
            break;
        }
    }
}

void GUI::WidgetUtil::select_combo_box_item_starting_with(QComboBox * combo_box, const QString &text) {
    for (int i = 0; i < combo_box->count(); ++i) {
        if (combo_box->itemText(i).startsWith(text)) {
            combo_box->setCurrentIndex(i);
            break;
        }
    }
}
