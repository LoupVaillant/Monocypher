
def number(limit, overflow):
    if limit > overflow:
        raise AssertionError("limit exceeds overflow", limit, overflow)
    return (limit, overflow)

def add   (a, b): return number(a[0] + b[0], max(a[1], b[1]))
def sub   (a, b): return number(a[0] + b[0], max(a[1], b[1])) # still +
def mul   (a, b): return number(a[0] * b[0], max(a[1], b[1]))
def rshift(a, n): return number(a[0] >> n, a[1])
def lshift(a, n): return number(a[0] << n, a[1])
def b_and (a, n): return number(a[0] & n, a[1])

inttype = int #we're overriding int down the line
def cast(n):
    if type(n) is inttype:
        return Number(number(n, 2**16-1))
    return n

class Number:
    def __init__  (self, num  ): self.num = num
    def limit     (self)       : return self.num[0]
    def overflow  (self)       : return self.num[1]
    def __add__   (self, other): return Number(add(self.num, cast(other.num)))
    def __sub__   (self, other): return Number(sub(self.num, cast(other.num)))
    def __mul__   (self, other): return Number(mul(self.num, cast(other.num)))
    def __rshift__(self, n)    : return Number(rshift(self.num, n))
    def __lshift__(self, n)    : return Number(lshift(self.num, n))
    def __and__   (self, n)    : return Number(b_and (self.num, n))
    def __str__(self): return "Number(" + str(self.num) + ")"

def make(num, limit, overflow):
    if num is not None:
        limit = num.limit()
    return Number(number(limit, overflow))

def u16(num=None, limit = 2**16-1): return make(num, limit, 2**16-1)
def u32(num=None, limit = 2**32-1): return make(num, limit, 2**32-1)
def u64(num=None, limit = 2**64-1): return make(num, limit, 2**64-1)
unsigned = u16

def i16(num=None, limit = 2**15-1): return make(num, limit, 2**15-1)
def i32(num=None, limit = 2**31-1): return make(num, limit, 2**31-1)
def i64(num=None, limit = 2**63-1): return make(num, limit, 2**63-1)
int = i16

def ASSERT(truth):
    if not truth:
        raise AssertionError("ASSERT failed")
