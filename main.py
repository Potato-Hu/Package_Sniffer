from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication,QMainWindow
import sys
from ui.Ui_sniffer import Ui_MainWindow
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QFileDialog,QMessageBox,QDockWidget,QListWidget,QTableWidget,QTableWidgetItem,QTextBrowser
from PyQt5.QtGui import *
from src.output import OutputToScreen
import os
import time


class Win_Main(QtWidgets.QMainWindow, Ui_MainWindow):

    def __init__(self):
        super(Win_Main, self).__init__()
        self.setupUi(self)
        self.start_sniffer.triggered.connect(self.StartSniff)
        self.stop_sniffer.triggered.connect(self.StopSniff)

    def StartSniff(self):
        sudopasswd = 'hzh'
        command = '--preserve-env PYTHONPATH=$(pwd) python3 src/packet_sniffer.py >> a.txt'
        os.system('echo %s|sudo -S %s' %(sudopasswd,command))
        f = open('a.txt','r',encoding='utf-8')
        text = f.read()
        self.textBrowser.setText(text)

#    def StopSniff(self):


if __name__=='__main__':
    app = QApplication(sys.argv)
    w = Win_Main()
    w.show()
    sys.exit(app.exec())