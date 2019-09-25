# -*- coding: utf-8 -*-


import wx
import mysql.connector as msc
from passlib.hash import pbkdf2_sha256


class MainWindow(wx.Frame):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title=title, size=(640, 480))

        # status bar
        self.CreateStatusBar()

        # sizer
        self.sizer = wx.BoxSizer(wx.HORIZONTAL)

        # menu
        filemenu = wx.Menu()
        menuConnect = filemenu.Append(
            wx.ID_NONE, "&Connect", "Connect to database")
        menuDisconnect = filemenu.Append(
            wx.ID_DEFAULT, "&Disconnect", "Disconnect from database")
        filemenu.AppendSeparator()
        menuExit = filemenu.Append(
            wx.ID_EXIT, "&Exit", "Terminate the program")

        # menu bar
        menubar = wx.MenuBar()
        menubar.Append(filemenu, "&Menu")
        self.SetMenuBar(menubar)

        # menu bindings
        self.Bind(wx.EVT_MENU, self.OnConnect, menuConnect)
        self.Bind(wx.EVT_MENU, self.OnDisconnect, menuDisconnect)
        self.Bind(wx.EVT_MENU, self.OnExit, menuExit)

        # text control (username & password field)
        self.userTxt = wx.TextCtrl(self, value="Username", size=(140, -1))
        self.passTxt = wx.TextCtrl(self, value="Password", size=(140, -1),
                                   style=wx.TE_PASSWORD)
        self.Bind(wx.EVT_TEXT, self.EvtUser, self.userTxt)
        self.Bind(wx.EVT_TEXT, self.EvtPass, self.passTxt)
        self.sizer.Add(self.userTxt, 1, wx.EXPAND)
        self.sizer.Add(self.passTxt, 1, wx.EXPAND)

        # send request button
        self.reqBtn = wx.Button(self, -1, "Send data")
        self.Bind(wx.EVT_BUTTON, self.OnSend, self.reqBtn)
        self.sizer.Add(self.reqBtn, 1, wx.EXPAND)

        # mysql stmt
        self.stmt = None
        self.cur = None

        # vars
        self.username = None
        self.password = None

        # frame settings
        self.SetSizer(self.sizer)
        self.SetAutoLayout(1)
        self.sizer.Fit(self)
        self.Show()

    def EvtUser(self, event):
        self.username = event.GetString()

    def EvtPass(self, event):
        self.password = event.GetString()

    def OnSend(self, event):
        if self.cur is not None:
            if self.username.strip() and self.password.strip():
                try:
                    req = (
                        "SELECT Username, Password FROM persons \
                            WHERE Username = %s")
                    self.cur.execute(req, (self.username,))
                    record = self.cur.fetchone()
                    if record is None:
                        req = (
                            "INSERT INTO persons (username, password) VALUES \
                                (%s, %s)")
                        self.cur.execute(req, (self.username,
                                         self.EncryptPassword(self.password)))
                        self.stmt.commit()
                    else:
                        if self.CheckEncrypted(self.password, record[1]):
                            self.ShowError("Information",
                                           f"Connected as {self.username}")
                        else:
                            self.ShowError("Error",
                                           "Wrong username or password!")
                except msc.Error as err:
                    print(err)
                finally:
                    print("Transaction done!")
            else:
                self.ShowError("Error", "Empty fields!")
        else:
            self.ShowError("Error", "You must be connected to database!")

    def EncryptPassword(self, password):
        return pbkdf2_sha256.hash(password)

    def CheckEncrypted(self, password, hashed):
        return pbkdf2_sha256.verify(password, hashed)

    def OnConnect(self, event):
        if self.stmt is None:
            try:
                self.stmt = msc.connect(
                    user='prout', password='prout', host='127.0.0.1',
                    database='wxClient')
                self.cur = self.stmt.cursor()
            except msc.Error as err:
                if err.errno == msc.errorcode.ER_ACCESS_DENIED_ERROR:
                    self.ShowError("Error", "Wrong username or password!")
                elif err.errno == msc.errorcode.ER_BAD_DB_ERROR:
                    self.ShowError("Error", "Database not found!")
                else:
                    print(err)
            else:
                print("Connected to database!")
        else:
            self.ShowError("Information", "Already connected to database!")

    def OnDisconnect(self, event):
        if self.stmt is not None:
            self.stmt.close()
            self.cur = None
            self.stmt = None
            print("Disconnected from database!")
        else:
            self.ShowError("Information", "Already disconnected from database!")

    def OnExit(self, event):
        if self.stmt is not None:
            self.OnDisconnect(None)
        self.Close(True)
        print("ByeBye")

    def ShowError(self, title, message):
        dlg = wx.MessageDialog(
            self, message, title, wx.OK)
        dlg.ShowModal()
        dlg.Destroy()


app = wx.App(False)
frame = MainWindow(None, 'wxClient')
app.MainLoop()
