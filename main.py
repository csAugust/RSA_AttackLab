from functools import reduce
from factordb.factordb import FactorDB
import libnum
import gmpy2
import threading
import primefac

def extendGCD(a, b):
    """
    扩展欧几里得算法;
    输入(a, b).
    返回(gcd, x, y): gcd是a、b的最大公约数，整数x、y（其中一个可能是负数）满足ax+by=gcd
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extendGCD(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    """
    求a对m的模逆元素;
    返回b: ab % m = 1.
    """
    gcd, x, y = extendGCD(a, m)
    if gcd != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


class Encrypter:
    """
    加密器类
    """
    def __init__(self):
        self.p = None
        self.q = None
        self.N = None
        self.r = None
        self.e = None
        self.d = None

    def set(self, *, p: int = None, q: int = None, e: int = None):
        """
        设置加密器参数

        :param p:
        :param q:
        :param e:
        :return: None
        """
        if p is not None:
            if libnum.prime_test(p):
                self.p = p
            else:
                raise ValueError("p 不是素数！")
        if q is not None:
            if libnum.prime_test(q):
                self.q = q
            else:
                raise ValueError("q 不是素数！")
        if e is not None:
            if self.r is None:
                raise ValueError("r 尚未被初始化！")
            if libnum.gcd(self.r, e) != 1:
                raise ValueError("e 不与 r 互素！")
            self.e = e
            self.d = libnum.invmod(self.e, self.r)  # 求得模反元素作为私钥

    def clear(self):
        """
        重置加密器

        :return: None
        """
        self.p = None
        self.q = None
        self.N = None
        self.r = None
        self.e = None
        self.d = None

    def init(self):
        """
        进行初始化N，r的计算

        :return: None
        """
        if self.p is None:
            raise ValueError("p 尚未被初始化！")
        if self.q is None:
            raise ValueError("q 尚未被初始化！")
        self.N = self.p * self.q
        self.r = (self.p - 1) * (self.q - 1)

    def encrypt(self, message: int) -> int:
        """
        加密明文

        :param message: 待加密的明文
        :return: 加密后的密文
        """
        if message >= self.N:
            raise ValueError("Message 超过了 N！")
        res = pow(message, self.e, self.N)
        return res


class Decrypter:
    """
    解密器
    """
    def __init__(self):
        self.p = None
        self.q = None
        self.N = None
        self.r = None
        self.e = None
        self.d = None

    def set(self, *, N: int = None, e: int = None, d: int = None):
        """
        设置解密器参数

        :param N:
        :param e:
        :param d:
        :return:
        """
        if N is not None:
            self.N = N
        if e is not None:
            self.e = e
        if d is not None:
            self.d = d

    def clear(self):
        """
        重置解密器

        :return:
        """
        self.p = None
        self.q = None
        self.N = None
        self.r = None
        self.e = None
        self.d = None

    def decrypt(self, c: int) -> int:
        """
        解密密文

        :param c: 待解密的密文
        :return: 解密后的明文
        """
        if self.d is None:
            raise ValueError("d 尚未被初始化！")
        res = pow(c, self.d, self.N)
        return res

    def DatabaseAttack(self):
        """
        在factorDB数据库中查询N能否被直接分解。
        解出data2 data6 data19
        :param c:
        :return: 明文m（数字形式）
        """
        if self.N is None:
            raise ValueError("N 尚未被初始化！")
        if self.e is None:
            raise ValueError("e 尚未被初始化！")
        factor = FactorDB(self.N)
        factor.connect()
        res = factor.get_factor_list()
        print(res)
        if (res is None) or (len(res) > 2) or factor.get_status() == 'C':
            raise RuntimeError(f'数据库分解失败 {self.N} 可能是因为输入了非法的N或N过大')
        p, q = res[0], res[1]
        r = (p - 1) * (q - 1)
        self.d = libnum.invmod(self.e, r)


def DatabaseAttack(N, e, c):
    """
    在factorDB数据库中查询N能否被直接分解。
    解出data2 data6 data19
    :param N:
    :param e:
    :param c:
    :return: 明文m（数字形式）
    """
    factor = FactorDB(N)
    factor.connect()
    res = factor.get_factor_list()
    print(res)
    if (res is None) or (len(res) > 2) or factor.get_status() == 'C':
        raise Exception(f"DatabaseAttack fails for N {N}")
    p, q = res[0], res[1]
    r = (p - 1) * (q - 1)
    d = libnum.invmod(e, r)
    m = pow(c, d, N)
    return m


def LowExpAttack(N, e, c, max_try, thread_num, start_at=0):
    """
    低加密指数爆破攻击。
    原理：由c=m^e(mod N)得到m^e=k*N+c，枚举k再开e次方。最多枚举start_at+max_try*thread_num次
    :param N:
    :param e:
    :param c:
    :param max_try: 每一个线程，k的最多枚举次数
    :param thread_num: 线程数
    :param start_at: k的起始值
    :return: 明文m（数字形式） 或 None（攻击失败）
    """

    def calc(N, e, c, k_lower, k_upper, result, thread_idx):
        k = k_lower
        while k < k_upper:
            res = gmpy2.iroot(c + k * N, e)
            if res[1]:
                result.append(res[0])
                return
            k += 1
        print(f'Thread {thread_idx} which tests [{k_lower},{k_upper}) fails and ends')

    result = []
    # thread_num threads, which thread i calculate [start_at+max_try*i, start_at+max_try*(i+1)]
    threads = [threading.Thread(target=calc,
                                args=(
                                    N, e, c, start_at + max_try * i, start_at + max_try * (i + 1), result, i))
               for i in range(0, thread_num)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if len(result) == 0:
        print(f"All threads fail to k: {thread_num * max_try + start_at}")
        return None
    else:
        return result[0]


def CRTAttack(Ns, e, cs):
    """
    低加密指数广播攻击（中国剩余定理）。
    原理：使用不同且互素的模数N、相同指数e且e较小，发送同一个数据m。根据中国剩余定理
    可以找到x满足x = c_i mod n_i forall i，对x开e次方就得到明文m。
    解出data3 data8 data12 data16 data20
    :param Ns:
    :param e:
    :param cs:
    :return: 明文m（数字形式） 或 None（攻击失败）
    """
    if libnum.gcd(*Ns) != 1:
        raise Exception("Input not pairwise co-prime")
    N_prod = reduce(lambda x, y: x * y, Ns)
    res = 0
    for c, N in zip(cs, Ns):
        m = N_prod // N
        m_inv = libnum.invmod(m, N)
        res += c * m * m_inv
        res %= N_prod
    m, succ = gmpy2.iroot(res, e)
    print(succ)
    return int(m)


def CMAAttack(N, es, cs):
    """
    共模攻击。
    原理：两组数据使用了相同的N，令e1s1+e2s2=1，则m=c1^s1*c2^s2 mod N
    解出 data0 data4
    :param N:
    :param es:
    :param cs:
    :return:明文m（数字形式）
    """
    assert len(es) == 2 and len(cs) == 2
    u, v, gcd = libnum.xgcd(es[0], es[1])
    if gcd != 1:
        raise Exception("e1 is not prime to e2")
    m = pow(cs[0], u, N) * pow(cs[1], v, N) % N
    return m


def MNPAttack(Ns, es, cs):
    """
    模不互素攻击。
    原理：两组数据使用的N不互素，则它们的最大公因数是它们各自的一个因子。
    解出 data1 data18
    :param Ns:
    :param es:
    :param cs:
    :return:明文列表ms（数字形式）
    """
    p = libnum.gcd(*Ns)
    assert p != 1
    qs = [N // p for N in Ns]
    ds = [libnum.invmod(e, (p - 1) * (q - 1)) for e, q in zip(es, qs)]
    ms = [pow(c, d, n) for c, d, n in zip(cs, ds, Ns)]
    return ms


def WienerAttack(N, e, c):
    """
    Wiener攻击。利用连分数分解近似得到ed，再解二元一次方程得到d
    :param N:
    :param e:
    :param c:
    :return: (p,q,k,d)
    """

    def continued_fractions_expansion(e, N):
        """
        将e/N展开为连分数。
        :param e:
        :param N:
        :return:
        """
        result = []
        divident = e % N
        quotient = e // N
        result.append(quotient)
        while divident != 0:
            e -= quotient * N
            N, e = e, N
            divident = e % N
            quotient = e // N
            result.append(quotient)
        return result

    def convergents(expansion):
        convergents = [(expansion[0], 1)]
        for i in range(1, len(expansion)):
            numerator = 1
            denominator = expansion[i]
            for j in range(i - 1, -1, -1):
                numerator += expansion[j] * denominator
                if j == 0:
                    break
                tmp = denominator
                denominator = numerator
                numerator = tmp
            convergents.append((numerator, denominator))  # (k,d)
        return convergents

    cons = convergents(continued_fractions_expansion(e, N))
    for cs in cons:
        k, d = cs
        if k == 0:
            continue
        phi_N = (e * d - 1) // k
        # x**2 - ((N - phi_N) + 1) * x + N = 0
        a = 1
        b = -((N - phi_N) + 1)
        c = N
        delta = b * b - 4 * a * c
        if delta <= 0:
            continue
        root = int(gmpy2.iroot(delta, 2)[0])
        x1 = (root - b) // (2 * a)
        x2 = -(root + b) // (2 * a)
        if x1 * x2 == N:
            return [x1, x2, k, d]


def CoppersmithAttack():
    pass


def Pollard(N):
    a = 2
    n = 2
    while True:
        a = pow(a, n, N)
        res = libnum.gcd(a - 1, N)
        if res != 1 and res != N:
            return res
        n += 1


def Williams(N):
    res = primefac.williams_pp1(N)
    return res


def read_file(file_name):
    """
    读取data数据。
    :param file_name:
    :return: (N, e, c)列表
    """
    with open(file_name) as file:
        data = file.readline(1024)
        N = data[0:256]
        e = data[256:512]
        c = data[512:768]
        return map(lambda x: (int)(x, base=16), (N, e, c))


def classify():
    Ns, es, cs = [], [], []
    for i in range(0, 21):
        (N, e, c) = read_file('./dataset/data' + str(i))
        # print(i, N, e, c, sep='\n')
        if e > 65537:
            print(i, e)
        Ns.append(N)
        es.append(e)
        cs.append(c)
    for i in range(0, 21):
        for j in range(0, 21):
            if i != j and libnum.gcd(Ns[i], Ns[j]) != 1:
                print(f'{i} not prime to {j}\n e is {es[i]}\n{es[j]}\n')


if __name__ == '__main__':
    """Ns, cs, es = [], [], []
    for i in [5, 9, 13, 14, 17]: # 5, 9, 13, 14, 17
        N, e, c = read_file("./dataset/data"+str(i))
        Ns.append(N)
        cs.append(c)
        es.append(e)
        print(i, e)
        print(N)
        print(c)
        print("-----------------")
        #res = primefac.pollard_pm1(N)
        #print(res)
    print(Ns)
    print(cs)"""
    N = 111178307033150739104608647474199786251516913698936331430121060587893564405482896814045419370401816305592149685291034839621072343496556225594365571727260237484885924615887468053644519779081871778996851601207571981072261232384577126377714005550318990486619636734701266032569413421915520143377137845245405768733
    res = primefac.pollard_pm1(N)

    print(res)
    # b0 = libnum.s2n(b'\x98vT2\x10\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    # b1 = libnum.s2n(b'\x98vT2\x10\xab\xcd\xef\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    # delta = b1 - b0
    # print(f'b0: {b0}\n')
    # print(f'delta: {delta}\n')
