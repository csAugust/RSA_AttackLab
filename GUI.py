import tkinter as tk
import gmpy2
import libnum
import main

WINDOW_WIDTH = 600
WINDOW_HEIGHT = 480


class EncryptFrame:
    def __init__(self, root):
        self.root = root
        self.frame = None
        self.init_frame()
        self.encrypter = main.Encrypter()

    def init_frame(self):
        self.frame = tk.Frame(self.root, width=WINDOW_WIDTH, height=WINDOW_HEIGHT, relief='groove')

        self.label_encrypt = tk.Label(self.frame, text='加密器')
        self.label_encrypt.place(relx=0.01, rely=0.01)

        self.check_show_vars_var = tk.IntVar()
        self.check_show_vars = tk.Checkbutton(self.frame, text='显示当前加密器属性', variable=self.check_show_vars_var,
                                              onvalue=1, offvalue=0, command=self.show_vars)
        self.check_show_vars.place(relx=0.5, rely=0.01)
        self.label_show_vars = tk.Label(self.frame, text='')
        self.label_show_vars.place(relx=0.5, rely=0.05)

        self.init_encrypt_byhand()
        self.init_encrypt_auto()

        self.label_m = tk.Label(self.frame, text='请输入明文')
        self.label_m.place(relx=0, rely=0.4)

        self.entry_m = tk.Entry(self.frame)
        self.entry_m.place(relx=0.1, rely=0.4, relwidth=0.2)

        self.button_confirm_m = tk.Button(self.frame, text='确认', command=self.confirm_m)
        self.button_confirm_m.place(relx=0.35, rely=0.4)

        self.label_hint = tk.Label(self.frame, text='')
        self.label_hint.place(relx=0.05, rely=0.5)

        self.label_encrypt_done = tk.Label(self.frame, text='')
        self.label_encrypt_done.place(relx=0.05, rely=0.6)

        self.frame.pack()

    def init_encrypt_byhand(self):
        self.label_p = tk.Label(self.frame, text='请输入p')
        self.label_p.place(relx=0.01, rely=0.1)

        self.entry_p = tk.Entry(self.frame)
        self.entry_p.place(relx=0.1, rely=0.1, relwidth=0.2)

        self.label_q = tk.Label(self.frame, text='请输入q')
        self.label_q.place(relx=0.01, rely=0.2)

        self.entry_q = tk.Entry(self.frame)
        self.entry_q.place(relx=0.1, rely=0.2, relwidth=0.2)

        self.button_confirm_pq = tk.Button(self.frame, text='确认', command=self.confirm_pq)
        self.button_confirm_pq.place(relx=0.35, rely=0.15)

        self.label_e = tk.Label(self.frame, text='请输入e')
        self.label_e.place(relx=0.01, rely=0.3)

        self.entry_e = tk.Entry(self.frame)
        self.entry_e.place(relx=0.1, rely=0.3, relwidth=0.2)

        self.button_confirm_e = tk.Button(self.frame, text='确认', command=self.confirm_e)
        self.button_confirm_e.place(relx=0.35, rely=0.3)

    def init_encrypt_auto(self):
        self.button_auto = tk.Button(self.frame, text='自动生成密钥', command=self.auto_confirm)
        self.button_auto.place(relx=0.2, rely=0.01)

        self.label_auto = tk.Label(self.frame, text='')
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

class DecryptFrame:
    def __init__(self, root):
        self.root = root
        self.frame = None
        self.init_frame()

    def init_frame(self):
        self.frame = tk.Frame(self.root, width=WINDOW_WIDTH, height=WINDOW_HEIGHT, relief='groove')
        self.label_en = tk.Label(self.frame, text='加密')
        self.label_en.place(relx=0.5, rely=0.5)
        self.frame.pack()


class MainPanel:
    def __init__(self):
        self.frame_encrypt = None
        self.frame_decrypt = None

    def start(self):
        self.root = tk.Tk()
        self.root.geometry(str(WINDOW_WIDTH)+'x'+str(WINDOW_HEIGHT))
        self.root.title("RSA工具")

        self.menu_main = tk.Menu(self.root)
        self.menu1 = tk.Menu(self.menu_main, tearoff=False)  # 菜单分组 menuFile
        self.menu_main.add_cascade(label="选项", menu=self.menu1)
        self.menu1.add_command(label="切换到加密器", command=self.change_to_encrypt)
        self.menu1.add_command(label="切换到解密器", command=self.change_to_decrypt)
        self.menu1.add_command(label="退出", command=self.root.destroy)
        self.root.config(menu=self.menu_main)

        self.frame_encrypt = EncryptFrame(self.root)

        self.root.mainloop()

    def change_to_encrypt(self):
        print("To encrypt")
        if self.frame_decrypt is not None:
            self.frame_decrypt.frame.destroy()
        if self.frame_encrypt is None:
            self.frame_encrypt = EncryptFrame(self.root)
        else:
            self.frame_encrypt.init_frame()

    def change_to_decrypt(self):
        print("To decrypt")
        if self.frame_encrypt is not None:
            self.frame_encrypt.frame.destroy()
        if self.frame_decrypt is None:
            self.frame_decrypt = DecryptFrame(self.root)
        else:
            self.frame_decrypt.init_frame()



if __name__ == '__main__':
    gui = MainPanel()
    gui.start()