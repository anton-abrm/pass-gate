#include "MainWindow.h"
#include <ui_MainWindow.h>

#include <memory>

#include <QMessageBox>
#include <QDebug>
#include <QString>
#include <QWindow>
#include <QTimer>
#include <QSettings>

#include <GUI/PinDialog.h>
#include <PKCS11/PKCS11.h>
#include <Password/Password.h>
#include <Keyboard/Keyboard.h>
#include <Convert/Convert.h>
#include <PKCS11/Exception.h>

static constexpr const char *c_configName = "pass-gate";
static constexpr const char *c_configPKCS11ProviderName = "pkcs11-provider";
static constexpr const char *c_configPublicKeyName = "public-key";

namespace GUI {

    MainWindow::MainWindow(QWidget *parent)
            : QMainWindow(parent), ui(new Ui::MainWindow) {

        ui->setupUi(this);

        connect(ui->go_button, &QPushButton::clicked, this, &MainWindow::go_button_clicked);
        connect(ui->apply_button, &QPushButton::clicked, this, &MainWindow::apply_button_clicked);
        connect(ui->enter_button, &QPushButton::clicked, this, &MainWindow::enter_button_clicked);
        connect(ui->clear_button, &QPushButton::clicked, this, &MainWindow::clear_button_clicked);
        connect(ui->pin_button, &QPushButton::clicked, this, &MainWindow::pin_button_clicked);
        connect(ui->show_secret_button, &QPushButton::pressed, this, &MainWindow::show_secret_button_pressed);
        connect(ui->show_secret_button, &QPushButton::released, this, &MainWindow::show_secret_button_released);

        this->setWindowFlags(this->windowFlags() | Qt::WindowStaysOnTopHint);

        ui->command_combo_box->addItem("Password", static_cast<int>(Command::Password));
        ui->command_combo_box->addItem("Keyfile", static_cast<int>(Command::Keyfile));
        ui->command_combo_box->addItem("Encrypt", static_cast<int>(Command::Encrypt));
        ui->command_combo_box->addItem("Decrypt", static_cast<int>(Command::Decrypt));

        QSettings settings(c_configName, c_configName);

        ui->pkcs11_line_edit->setText(settings.value(c_configPKCS11ProviderName).toString());

        PKCS11::set_pin_callback([this](std::u8string &pin) -> bool {

            PinDialog dlg(this);

            dlg.setModal(true);

            if (!dlg.exec())
                return false;

            pin = Convert::to_u8string(dlg.pin());

            return true;
        });

        PKCS11::set_slot_callback([this]() {
            QTimer::singleShot(0, this, &MainWindow::update_certificates);
        });

        PKCS11::initialize();

        QTimer::singleShot(0, this, &MainWindow::apply_provider);
    }

    MainWindow::~MainWindow() {
        PKCS11::terminate();
        delete ui;
    }

    void MainWindow::go_button_clicked() {
        try {

            const auto cert_id_bytes = ui->key_combo_box->currentData().toByteArray();

            const auto certificate = PKCS11::RSACertificate::get_certificate(
                    Convert::to_const_span(cert_id_bytes));

            switch (static_cast<Command>(ui->command_combo_box->currentData().toInt())) {

                case Command::Password:
                    make_password(*certificate);
                    break;

                case Command::Keyfile:
                    make_keyfile(*certificate);
                    break;

                case Command::Encrypt:
                    encrypt(*certificate);
                    break;

                case Command::Decrypt:
                    decrypt(*certificate);
                    break;
            }
        }
        catch (const std::exception &ex) {
            QMessageBox::warning(this, "Error", ex.what());
        }
    }

    void MainWindow::show_secret_button_pressed() {
        ui->secret_line_edit->setEchoMode(QLineEdit::EchoMode::Normal);
    }

    void MainWindow::show_secret_button_released() {
        ui->secret_line_edit->setEchoMode(QLineEdit::EchoMode::Password);
    }

    void MainWindow::clear_button_clicked() {
        ui->data_plain_edit->clear();
    }

    void MainWindow::enter_button_clicked() {
        Keyboard::enter_text(
                Convert::to_u8string(
                        ui->secret_line_edit->text()));
    }

    void MainWindow::encrypt(const PKCS11::RSACertificate &certificate) {
        const auto data = ui->secret_line_edit->text()
                .trimmed()
                .toUtf8();

        auto cipher = certificate.encrypt(Convert::to_const_span(data));

        ui->data_plain_edit->setPlainText(
                Convert::to_qt_byte_array(cipher).toBase64());
    }

    void MainWindow::make_password(const PKCS11::RSACertificate &certificate) {

        const auto data = ui->source_line_edit->text()
                .trimmed()
                .toUtf8();

        const auto sign = certificate.sign(
                Convert::to_const_span(data));

        auto format = ui->format_combo_box->currentText().toLatin1();

        int index{0};
        auto pass = Password::generate(format.constData(), [&]() -> int16_t {
            return index < sign.size()
                   ? static_cast<int16_t>(sign.at(index++))
                   : static_cast<int16_t>(-1);
        });

        ui->secret_line_edit->setText(
                QString::fromStdString(pass));
    }

    void MainWindow::make_keyfile(const PKCS11::RSACertificate &certificate) {

        const auto data = ui->source_line_edit->text()
                .trimmed()
                .toUtf8();

        const auto sign = certificate.sign(
                Convert::to_const_span(data));

        ui->data_plain_edit->setPlainText(
                Convert::to_qt_byte_array(sign).toBase64());
    }

    void MainWindow::decrypt(const PKCS11::RSACertificate &certificate) {

        auto cipher = QByteArray::fromBase64(
                ui->data_plain_edit->toPlainText().trimmed().toLatin1());

        auto data = certificate.decrypt(
                Convert::to_const_span(cipher));

        ui->secret_line_edit->setText(
                Convert::to_qt_string_from_utf8(data));
    }

    void MainWindow::apply_button_clicked() {
        apply_provider();
    }

    void MainWindow::update_certificates() {

        if (ui->key_combo_box->count() != 0)
            return;

        auto certificates = PKCS11::get_certificates();

        for (const auto &certificate: certificates) {

            auto common_name = Convert::to_qt_string(certificate.common_name());
            auto rsa_modulus = Convert::to_qt_byte_array(certificate.rsa_modulus()).toHex().toUpper();

            rsa_modulus.truncate(8);

            QString text;

            text.append(rsa_modulus);
            text.append(" | ");
            text.append(common_name);

            auto id = Convert::to_qt_byte_array(certificate.id());

            ui->key_combo_box->addItem(text, id);
        }

        QSettings settings(c_configName, c_configName);

        auto public_key = settings.value(c_configPublicKeyName).toString();

        ui->key_combo_box->setCurrentIndex(
                ui->key_combo_box->findText(public_key, Qt::MatchStartsWith));
    }

    void MainWindow::apply_provider() {

        ui->key_combo_box->clear();

        try {
            PKCS11::remove_provider(u8"pkcs11");
        }
        catch (const PKCS11::Exception &) {
        }

        if (!ui->pkcs11_line_edit->text().isEmpty()) {
            try {
                PKCS11::add_provider(u8"pkcs11", Convert::to_u8string(
                        ui->pkcs11_line_edit->text()));
            }
            catch (const PKCS11::Exception &ex) {
                QMessageBox::warning(this, "Error", ex.what());
                return;
            }

            update_certificates();
        }

        QSettings settings(c_configName, c_configName);

        settings.setValue(c_configPKCS11ProviderName, ui->pkcs11_line_edit->text());
    }

    void MainWindow::pin_button_clicked() {

        QSettings settings(c_configName, c_configName);

        settings.setValue(c_configPublicKeyName, ui->key_combo_box->currentText().left(8));
    }
}