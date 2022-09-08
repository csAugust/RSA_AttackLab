# 一个简单的RSA加密和解密器
# RSA破译部分代码请参见RSAAttackReport.ipynb

from random import randint
import tkinter as tk
import gmpy2
import libnum
import main

WINDOW_WIDTH = 600
WINDOW_HEIGHT = 480


class EncryptFrame:
    """
    解密界面
    """
    def __init__(self, root):
        self.root = root
        self.frame = None
        self.init_frame()
        self.encrypter = main.Encrypter()
        self.c = None

    def save(self):
        path = './encrypt_data.txt'
        with open(path, 'w') as file:
            file.writelines(f'N {self.encrypter.N}\n')
            file.writelines(f'e {self.encrypter.e}\n')
            file.writelines(f'd {self.encrypter.d}\n')
            file.writelines(f'c {self.c}\n')

    def init_frame(self):
        """
        初始化frame

        :return: None
        """
        self.frame = tk.Frame(self.root, width=WINDOW_WIDTH, height=WINDOW_HEIGHT, relief='groove')

        self.label_encrypt = tk.Label(self.frame, text='加密器')
        self.label_encrypt.place(relx=0.01, rely=0.01)

        self.button_show_vars = tk.Button(self.frame, text='显示当前加密器属性', command=self.show_vars)
        self.button_show_vars.place(relx=0.5, rely=0.01)

        self.label_show_vars = tk.Label(self.frame, text='', anchor='w', justify='left')
        self.label_show_vars.place(relx=0.5, rely=0.08)

        self.init_encrypt_byhand()
        self.init_encrypt_auto()

        self.label_m = tk.Label(self.frame, text='请输入明文')
        self.label_m.place(relx=0, rely=0.5)

        self.entry_m = tk.Entry(self.frame)
        self.entry_m.place(relx=0.1, rely=0.5, relwidth=0.2)

        self.button_confirm_m = tk.Button(self.frame, text='确认', command=self.confirm_m)
        self.button_confirm_m.place(relx=0.35, rely=0.5)

        self.check_string_m_var = tk.IntVar()
        self.check_string_m = tk.Checkbutton(self.frame, text='以数值形式输入', variable=self.check_string_m_var,
                                             onvalue=1, offvalue=0)
        self.check_string_m.place(relx=0.01, rely=0.55)

        self.check_padding_var = tk.IntVar()
        self.check_padding = tk.Checkbutton(self.frame, text='启用随机填充', variable=self.check_padding_var,
                                             onvalue=1, offvalue=0, command=self.use_padding)
        self.check_padding.place(relx=0.01, rely=0.6)

        self.label_hint = tk.Label(self.frame, text='')
        self.label_hint.place(relx=0.05, rely=0.7)

        self.label_encrypt_done = tk.Label(self.frame, text='', anchor='w', justify='left')
        self.label_encrypt_done.place(relx=0.05, rely=0.8)

        self.frame.pack()

    def init_encrypt_byhand(self):
        """
        初始化手动加密参数设置部分，包含p q e 的输入及确认

        :return: None
        """
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
        """
        初始化自动生成密钥部分，包含选择N的位数

        :return: None
        """
        self.scale_prime_bits_var = tk.IntVar()
        self.scale_prime_bits_var.set(32)
        self.scale_prime_bits = tk.Scale(self.frame, orient=tk.HORIZONTAL, length=260, from_=8, to=1024,
                                         label='选择自动生成N的位数', tickinterval=128, resolution=8, variable=self.scale_prime_bits_var)
        self.scale_prime_bits.place(relx=0.5, rely=0.2)

        self.button_auto = tk.Button(self.frame, text='自动生成并提交p、q、e', command=self.auto_confirm)
        self.button_auto.place(relx=0.5, rely=0.4)

        self.label_auto = tk.Label(self.frame, text='', anchor='w', justify='left')
        self.label_auto.place(relx=0.5, rely=0.5)

    def show_vars(self):
        """
        显示当前加密器密钥

        :return: None
        """
        self.label_show_vars.config(text=f'N:{self.encrypter.N}\ne:{self.encrypter.e}\nd:{self.encrypter.d}')

    def confirm_pq(self):
        """
        提交p q
        """
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
        """
        提交e
        """
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
        """
        提交m
        """
        def padding(m):
            print(bin(m))
            m_len = len(bin(m))
            PADDING_BITS = self.scale_padding_bits.get()
            if PADDING_BITS - m_len <= 64:
                return m
            FLAG_BITS = 64
            flag = randint(1, 1 << FLAG_BITS)
            m = m | (flag << (PADDING_BITS - FLAG_BITS))
            print(bin(m))
            return m

        res = None
        m = self.entry_m.get()
        if self.check_string_m_var.get() == 1:
            try:
                m = int(m)
            except ValueError:
                self.label_hint.config(text='请输入整数！')
                return
        else:
            m = libnum.s2n(m)
        try:
            if self.check_padding_var.get() == 1:
                m = padding(m)
            res = self.encrypter.encrypt(m)
            self.label_encrypt_done.config(text=f'加密结果为 {res}')
            self.c = res
        except ValueError as e:
            self.label_hint.config(text=f'发生错误 {e}')

    def auto_confirm(self):
        """
        自动生成密钥并提交

        :return: None
        """
        PRIME_BITS = self.scale_prime_bits_var.get() // 2
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
            self.label_auto.config(text=f'选取结果如下:\np: {p}\nq: {q}\ne: {e}\nd: {self.encrypter.d}\nN: {self.encrypter.N}')
        except ValueError as err:
            self.label_hint.config(text=f'发生错误 {err}')

    def use_padding(self):
        """
        启用随机填充后更新界面

        :return: None
        """
        if self.check_padding_var.get() == 1:
            self.label_hint.place(relx=0.05, rely=0.85)
            self.label_encrypt_done.place(relx=0.05, rely=0.9)

            self.scale_padding_bits_var = tk.IntVar()
            self.scale_padding_bits_var.set(32)
            self.scale_padding_bits = tk.Scale(self.frame, orient=tk.HORIZONTAL, length=140, from_=128, to=512,
                                             label='选择将明文填充到的位数', tickinterval=128, resolution=8, variable=self.scale_padding_bits_var)
            self.scale_padding_bits.place(relx=0.05, rely=0.65)
        else:
            self.label_hint.place(relx=0.05, rely=0.7)
            self.label_encrypt_done.place(relx=0.05, rely=0.8)
            self.scale_padding_bits.destroy()



class DecryptFrame:
    """
    解密界面
    """
    def __init__(self, root):
        self.root = root
        self.frame = None
        self.init_frame()
        self.decrypter = main.Decrypter()
        self.m = None

    def save(self):
        path = './decrypt_data.txt'
        with open(path, 'w') as file:
            file.writelines(f'N {self.decrypter.N}\n')
            file.writelines(f'e {self.decrypter.e}\n')
            file.writelines(f'd {self.decrypter.d}\n')
            file.writelines(f'm {self.m}\n')

    def init_frame(self):
        """
        初始化frame

        :return: None
        """
        self.frame = tk.Frame(self.root, width=WINDOW_WIDTH, height=WINDOW_HEIGHT, relief='groove')

        self.label_encrypt = tk.Label(self.frame, text='解密器')
        self.label_encrypt.place(relx=0.01, rely=0.01)

        self.button_show_vars = tk.Button(self.frame, text='显示当前解密器属性', command=self.show_vars)
        self.button_show_vars.place(relx=0.5, rely=0.01)
        self.label_show_vars = tk.Label(self.frame, text='')
        self.label_show_vars.place(relx=0.5, rely=0.08)

        self.init_decrypt_byhand()
        self.init_decrypt_auto()

        self.label_c = tk.Label(self.frame, text='请输入密文')
        self.label_c.place(relx=0, rely=0.5)

        self.entry_c = tk.Entry(self.frame)
        self.entry_c.place(relx=0.1, rely=0.5, relwidth=0.2)

        self.button_confirm_c = tk.Button(self.frame, text='确认', command=self.confirm_c)
        self.button_confirm_c.place(relx=0.35, rely=0.5)

        self.check_string_c_var = tk.IntVar()
        self.check_string_c = tk.Checkbutton(self.frame, text='以字节序列形式输出', variable=self.check_string_c_var,
                                             onvalue=1, offvalue=0)
        self.check_string_c.place(relx=0.01, rely=0.55)

        self.label_hint = tk.Label(self.frame, text='')
        self.label_hint.place(relx=0.05, rely=0.6)

        self.label_decrypt_done = tk.Label(self.frame, text='')
        self.label_decrypt_done.place(relx=0.05, rely=0.7)

        self.frame.pack()

    def init_decrypt_byhand(self):
        """
        初始化手动解密参数设置部分，包含N e d的输入及确认

        :return: None
        """
        self.label_N = tk.Label(self.frame, text='请输入N')
        self.label_N.place(relx=0.01, rely=0.1)

        self.entry_N = tk.Entry(self.frame)
        self.entry_N.place(relx=0.1, rely=0.1, relwidth=0.2)

        self.label_e = tk.Label(self.frame, text='请输入e')
        self.label_e.place(relx=0.01, rely=0.2)

        self.entry_e = tk.Entry(self.frame)
        self.entry_e.place(relx=0.1, rely=0.2, relwidth=0.2)

        self.button_confirm_Ne = tk.Button(self.frame, text='确认', command=self.confirm_Ne)
        self.button_confirm_Ne.place(relx=0.35, rely=0.15)

        self.label_d = tk.Label(self.frame, text='请输入d')
        self.label_d.place(relx=0.01, rely=0.3)

        self.entry_d = tk.Entry(self.frame)
        self.entry_d.place(relx=0.1, rely=0.3, relwidth=0.2)

        self.button_confirm_d = tk.Button(self.frame, text='确认', command=self.confirm_d)
        self.button_confirm_d.place(relx=0.35, rely=0.3)

    def init_decrypt_auto(self):
        self.button_database = tk.Button(self.frame, text='数据库分解N', command=self.do_DatabaseAttack)
        self.button_database.place(relx=0.5, rely=0.4)

        self.label_auto = tk.Label(self.frame, text='')
        self.label_auto.place(relx=0.5, rely=0.5)

    def show_vars(self):
        """
        显示当前解密器密钥

        :return: None
        """
        self.label_show_vars.config(text=f'N:{self.decrypter.N}\ne:{self.decrypter.e}\nd:{self.decrypter.d}')

    def confirm_Ne(self):
        """
        提交N e
        """
        N = self.entry_N.get()
        e = self.entry_e.get()
        try:
            N = int(N)
            e = int(e)
        except ValueError:
            self.label_hint.config(text='请输入整数！')
            return
        try:
            self.decrypter.set(N=N, e=e)
            self.label_hint.config(text=f'选取的N为 {N}，e为 {e}')
        except ValueError as err:
            self.label_hint.config(text=f'发生错误 {err}')

    def confirm_d(self):
        """
        提交d
        """
        d = self.entry_d.get()
        try:
            d = int(d)
        except ValueError:
            self.label_hint.config(text='请输入整数！')
            return
        try:
            self.decrypter.set(d=d)
            self.label_hint.config(text=f'选取的d为 {d}')
        except ValueError as err:
            self.label_hint.config(text=f'发生错误 {err}')

    def confirm_c(self):
        """
        提交c
        """
        res = None
        c = self.entry_c.get()
        try:
            c = int(c)
        except ValueError:
            self.label_hint.config(text='请输入整数！')
            return
        try:
            res = self.decrypter.decrypt(c)
            if self.check_string_c_var.get() == 1:
                res = libnum.n2s(res)
            self.label_decrypt_done.config(text=f'解密结果为{res}')
            self.m = res
        except ValueError as e:
            self.label_hint.config(text=f'发生错误 {e}')

    def do_DatabaseAttack(self):
        try:
            self.decrypter.DatabaseAttack()
            self.label_auto.config(text=f'数据库分解成功\nd:{self.decrypter.d}')
        except (ValueError, RuntimeError) as e:
            self.label_hint.config(text=f'发生错误 {e}')


class MainPanel:
    """
    主面板
    """
    def __init__(self):
        self.frame_encrypt = None
        self.frame_decrypt = None
        self.mode = 1

    def start(self):
        """
        启动
        """
        self.root = tk.Tk()
        self.root.geometry(str(WINDOW_WIDTH)+'x'+str(WINDOW_HEIGHT))
        self.root.title("RSA工具")

        self.menu_main = tk.Menu(self.root)
        self.menu1 = tk.Menu(self.menu_main, tearoff=False)  # 菜单分组 menuFile
        self.menu_main.add_cascade(label="选项", menu=self.menu1)
        self.menu1.add_command(label="保存当前结果", command=self.save)
        self.menu1.add_command(label="切换到加密器", command=self.change_to_encrypt)
        self.menu1.add_command(label="切换到解密器", command=self.change_to_decrypt)
        self.menu1.add_command(label="退出", command=self.root.destroy)
        self.root.config(menu=self.menu_main)

        self.frame_encrypt = EncryptFrame(self.root)

        self.root.mainloop()

    def save(self):
        if self.mode == 1:
            self.frame_encrypt.save()
        if self.mode == 2:
            self.frame_decrypt.save()

    def change_to_encrypt(self):
        """
        切换到加密界面
        """
        print("To encrypt")
        self.mode = 1
        if self.frame_decrypt is not None:
            self.frame_decrypt.frame.destroy()
        if self.frame_encrypt is None:
            self.frame_encrypt = EncryptFrame(self.root)
        else:
            self.frame_encrypt.init_frame()

    def change_to_decrypt(self):
        """
        切换到解密界面
        """
        print("To decrypt")
        self.mode = 2
        if self.frame_encrypt is not None:
            self.frame_encrypt.frame.destroy()
        if self.frame_decrypt is None:
            self.frame_decrypt = DecryptFrame(self.root)
        else:
            self.frame_decrypt.init_frame()


if __name__ == '__main__':
    gui = MainPanel()
    gui.start()