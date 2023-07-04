# Hastad’s Broadcast Attack
Hack The Box の問題を解く過程で Hastad’s Broadcast Attack というRSA暗号に対する攻撃方法を学んだので、その紹介と実装をします。  

## 攻撃成立条件
Hastad’s Broadcast Attack (以下、単に攻撃とします。) が成立するための条件は  
同一の平文を異なる$n$で暗号化した暗号文と$n$のペアが$e$個判明していること。   
です。 

## 攻撃方法
$e=3$ として考える。  
中国剰余定理より、以下を満たす値 $x$ が $0＜x≦n_1n_2n_3$ の範囲に必ず一つだけ存在する。  
$x≡c_1\pmod{n_1}$  
$x≡c_2\pmod{n_2}$  
$x≡c_3\pmod{n_3}$  
また、RSAの定義より、  
$x≡m^3\pmod{n}$ なので $m^3≦n_1n_2n_3$ のとき $x=m^3$ となるので $m=x^{\frac{1}{3}}$ で $m$を求めることができる。  
つまり $x$ を求めることができれば平文が判明する。  

## 一般化
$x≡c_1\pmod{n_1}$  
$x≡c_2\pmod{n_2}$  
$x≡c_3\pmod{n_3}$   
$\ \ \ \ \ \ \ \ \ \ \ \ \vdots$  
$x≡c_e\pmod{n_e}$
を満たす $x$ は中国剰余定理より  
    
$S=n_1\times n_2\times n_3\times\cdots\times n_e$  
$t_1=(\frac{S}{n_1})^{-1}\pmod{n_1}$  
$t_2=(\frac{S}{n_2})^{-1}\pmod{n_2}$  
$t_3=(\frac{S}{n_3})^{-1}\pmod{n_3}$  
$\ \ \ \ \ \ \ \vdots$  
$t_e=(\frac{S}{n_e})^{-1}\pmod{n_e}$  
としたとき

$x=t_1(\frac{S}{n_1})\times c_1+t_2(\frac{S}{n_2})\times c_2+t_3(\frac{S}{n_3})\times c_3 + \cdots t_e(\frac{S}{n_e})\times c_e$  
となる。そして平文は  
$m=x^{\frac{1}{e}}$  

$x$の求め方についてですが、中国剰余定理の証明(ガウスの証明)に使われている式を使っています。一般的によく説明される証明方法の方ではないゆえ、混乱するかもしれないので書いておきます。

## 実装
```python
from gmpy2 import invert,iroot as ir
import sys
from Crypto.Util.number import long_to_bytes

c1 = "redacted"
c2 = "redacted"
c3 = "redacted"
n1 = "redacted"
n2 = "redacted"
n3 = "redacted"
e = 3

def mlt_any(lst):
    r = 1
    for i in range(len(lst)):
        r *= lst[i]
    return r


def crt(N,C):
    # N = [n1,n2,n3, .... ,ne]
    # C = [c1,c2,c3, .... ,ce]
    try:
        assert len(N) == len(C)
    except AssertionError:
        print("Error: N and C must have the same length")
        sys.exit(1)

    try:
        assert len(N) >= e
    except AssertionError:
        print("Error: number of pairs (n,c) must be same as e")
        sys.exit(1)

    N = N[0:e]
    C = C[0:e]

    mlta = mlt_any(N)

    print("modulo:", mlta)
    total = 0
    for (ni,ci) in zip(N,C):
        p = mlta // ni
        total += ci * invert(p,ni) * p

    return total % mlta

def iroot(x):
    m,is_valid = ir(x,e)
    if is_valid:
        print("plain text: ",long_to_bytes(m))
    else:
        print("couldn't find any plain text")

def main():
    C = [c1,c2,c3]
    N = [n1,n2,n3]
    x = crt(N,C)
    iroot(x)


if __name__ == "__main__":
    main()
```

## 参考にしたもの
### 中国剰余定理
https://ja.wikipedia.org/wiki/%E4%B8%AD%E5%9B%BD%E3%81%AE%E5%89%B0%E4%BD%99%E5%AE%9A%E7%90%86  
https://www.youtube.com/watch?v=LNQH8d5dEgw  
### その他 
https://ja.wikipedia.org/wiki/%E3%83%A2%E3%82%B8%E3%83%A5%E3%83%A9%E9%80%86%E6%95%B0  