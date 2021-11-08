#pragma once

#include <QMainWindow>
#include <PKCS11/RSACertificate.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

namespace GUI {

    class MainWindow : public QMainWindow {
    Q_OBJECT

    public:
        explicit MainWindow(QWidget *parent = nullptr);
        ~MainWindow() override;

    private:

        enum class Command {
            Encrypt,
            Decrypt,
            Keyfile,
            Password
        };

        void apply_provider();
        void update_certificates();

        void encrypt(const PKCS11::RSACertificate &);
        void decrypt(const PKCS11::RSACertificate &);
        void make_keyfile(const PKCS11::RSACertificate &);
        void make_password(const PKCS11::RSACertificate &);

    private slots:

        void pin_button_clicked();
        void go_button_clicked();
        void apply_button_clicked();
        void show_secret_button_pressed();
        void show_secret_button_released();
        void enter_button_clicked();
        void clear_button_clicked();

    private:
        Ui::MainWindow *ui;
    };
}