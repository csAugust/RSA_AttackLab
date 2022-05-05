import tkinter as tk

import main


class MainPanel:
    def __init__(self):
        self.encoder = main.Encoder()

    def start(self):
        self.root = tk.Tk()
        self.root.geometry('600x480')
        self.root.title("RSA工具")

        self.label_hint = tk.Label(self.root, text='')
        self.label_hint.grid(row=1, column=4, columnspan=2)

        self.label_encrypt = tk.Label(self.root, text='加密')
        self.label_encrypt.grid(row=0, column=0)
        #self.label_encrypt.place(relx=0.1, rely=0.2)

        self.label_p = tk.Label(self.root, text='请输入p')
        self.label_p.grid(row=1, column=0)

        self.entry_p = tk.Entry(self.root)
        self.entry_p.grid(row=1, column=1, columnspan=2)

        self.label_q = tk.Label(self.root, text='请输入q')
        self.label_q.grid(row=2, column=0)

        self.entry_q = tk.Entry(self.root)
        self.entry_q.grid(row=2, column=1, columnspan=2)

        self.button_confirm_pq = tk.Button(self.root, text='确认', command=self.confirm_pq)
        self.button_confirm_pq.grid(row=3, column=1)

        self.root.mainloop()

    def confirm_pq(self):
        p = self.entry_p.get()
        q = self.entry_q.get()
        self.label_hint.config(text=p+' '+q)
        try:
            p = int(p)
            q = int(q)
        except ValueError:
            self.label_hint.config(text='请输入整数！')
            return
        print(p+q)

if __name__ == '__main__':
    gui = MainPanel()
    gui.start()