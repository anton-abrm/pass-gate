#include "PinDialog.h"
#include <ui_PinDialog.h>

namespace GUI {

    PinDialog::PinDialog(QWidget *parent) :
            QDialog(parent),
            ui(new Ui::PinDialog) {
        ui->setupUi(this);
    }

    PinDialog::~PinDialog() {
        delete ui;
    }

    QString PinDialog::pin() const {
        return ui->lePin->text();
    }
}
