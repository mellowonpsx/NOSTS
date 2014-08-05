#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->outputTextBox->setReadOnly(true);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::addTextOutput(const QString &text)
{
    QString newText = ui->outputTextBox->toPlainText();
    newText.append(text);
    ui->outputTextBox->setPlainText(newText);
}
