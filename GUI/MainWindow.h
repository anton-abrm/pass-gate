#pragma once

#include <QMainWindow>

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

        void encrypt(void * cert);
        void decrypt(void * cert);
        void make_keyfile(void * cert);
        void make_password(void * cert);

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