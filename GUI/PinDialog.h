#pragma once

#include <QDialog>

namespace Ui {
class PinDialog;
}

namespace GUI {

    class PinDialog : public QDialog {
    Q_OBJECT

    public:
        explicit PinDialog(QWidget *parent = nullptr);

        ~PinDialog();

        QString pin() const;

    private:
        Ui::PinDialog *ui;
    };
}
