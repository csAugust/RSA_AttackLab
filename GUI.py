import tkinter as tk

import gmpy2
import libnum

import main


class MainPanel:
    def __init__(self):
        self.encrypter = main.Encrypter()

    def start(self):
        self.root = tk.Tk()
        self.root.geometry('600x480')
        self.root.title("RSA工具")

        self.label_encrypt = tk.Label(self.root, text='加密')
        self.label_encrypt.place(relx=0.01, rely=0.01)

        self.check_show_vars_var = tk.IntVar()
        self.check_show_vars = tk.Checkbutton(self.root, text='显示当前加密器属性', variable=self.check_show_vars_var,
                                              onvalue=1, offvalue=0, command=self.show_vars)
        self.check_show_vars.place(relx=0.5, rely=0.01)
        self.label_show_vars = tk.Label(self.root, text='')
        self.label_show_vars.place(relx=0.5, rely=0.05)

        self.init_encrypt_byhand()
        self.init_encrypt_auto()

        self.label_m = tk.Label(self.root, text='请输入明文')
        self.label_m.place(relx=0, rely=0.4)

        self.entry_m = tk.Entry(self.root)
        self.entry_m.place(relx=0.1, rely=0.4, relwidth=0.2)

        self.button_confirm_m = tk.Button(self.root, text='确认', command=self.confirm_m)
        self.button_confirm_m.place(relx=0.35, rely=0.4)

        self.label_hint = tk.Label(self.root, text='')
        self.label_hint.place(relx=0.05, rely=0.5)

        self.label_encrypt_done = tk.Label(self.root, text='')
        self.label_encrypt_done.place(relx=0.05, rely=0.6)

        self.root.mainloop()

    def init_encrypt_byhand(self):
        self.label_p = tk.Label(self.root, text='请输入p')
        self.label_p.place(relx=0.01, rely=0.1)

        self.entry_p = tk.Entry(self.root)
        self.entry_p.place(relx=0.1, rely=0.1, relwidth=0.2)

        self.label_q = tk.Label(self.root, text='请输入q')
        self.label_q.place(relx=0.01, rely=0.2)

        self.entry_q = tk.Entry(self.root)
        self.entry_q.place(relx=0.1, rely=0.2, relwidth=0.2)

        self.button_confirm_pq = tk.Button(self.root, text='确认', command=self.confirm_pq)
        self.button_confirm_pq.place(relx=0.35, rely=0.15)

        self.label_e = tk.Label(self.root, text='请输入e')
        self.label_e.place(relx=0.01, rely=0.3)

        self.entry_e = tk.Entry(self.root)
        self.entry_e.place(relx=0.1, rely=0.3, relwidth=0.2)

        self.button_confirm_e = tk.Button(self.root, text='确认', command=self.confirm_e)
        self.button_confirm_e.place(relx=0.35, rely=0.3)

    def init_encrypt_auto(self):
        self.button_auto = tk.Button(self.root, text='自动生成密钥', command=self.auto_confirm)
        self.button_auto.place(relx=0.2, rely=0.01)

        self.label_auto = tk.Label(self.root, text='')
        self.label_auto.place(relx=0.5, rely=0.2)

    def show_vars(self):
        self.label_show_vars.config(text=f'N:{self.encrypter.N}\ne:{self.encrypter.e}\nd:{self.encrypter.d}')

    def confirm_pq(self):
        p = self.entry_p.get()
        q = self.entry_q.get()
        try:
            p = int(p)
            q = int(q)
        except ValueError:
            self.label_hint.config(text='请输入整数！')
            return
        try:
            self.encrypter.set(p=p, q=q)
            self.encrypter.init()
            self.label_hint.config(text=f'选取的p为 {p}，q为 {q}')
        except ValueError as e:
            self.label_hint.config(text=f'发生错误 {e}')

    def confirm_e(self):
        e = self.entry_e.get()
        try:
            e = int(e)
        except ValueError:
            self.label_hint.config(text='请输入整数！')
            return
        try:
            self.encrypter.set(e=e)
            self.label_hint.config(text=f'选取的e为 {e}')
        except ValueError as err:
            self.label_hint.config(text=f'发生错误 {err}')

    def confirm_m(self):
        res = None
        m = self.entry_m.get()
        try:
            m = int(m)
        except ValueError:
            self.label_hint.config(text='请输入整数！')
            return
        try:
            res = self.encrypter.encrypt(m)
            self.label_encrypt_done.config(text=f'加密结果为{res}')
        except ValueError as e:
            self.label_hint.config(text=f'发生错误 {e}')

    def auto_confirm(self):
        PRIME_BITS = 8
        E = 65537
        p = libnum.generate_prime(PRIME_BITS)
        q = libnum.generate_prime(PRIME_BITS)
        try:
            self.encrypter.set(p=p, q=q)
            self.encrypter.init()
            e = E
            if libnum.gcd(self.encrypter.r, e) != 1:
                e = gmpy2.next_prime(e)
            self.encrypter.set(e=e)
            self.label_auto.config(text=f'选取的p为 {p}\nq为 {q}\ne为 {e}\nd为{self.encrypter.d}')
        except ValueError as err:
            self.label_hint.config(text=f'发生错误 {err}')



if __name__ == '__main__':
    gui = MainPanel()
    gui.start()