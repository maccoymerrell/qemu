import sys
H=b'0123456789abcdef'
def hx(w):
    b=bytearray(9)
    for i in range(4):
        v=(w>>(8*i))&255
        b[2*i]=H[v>>4]; b[2*i+1]=H[v&15]
    b[8]=10
    return bytes(b)
out=sys.stdout.buffer
fills=[(1,2),(31,0),(30,0),(0,1),(0,3),(0,0),(1,1)]
buf=bytearray()
for top in range(1<<22):
    for rn,rd in fills:
        buf+=hx((top<<10)|(rn<<5)|rd)
    if len(buf)>1<<20:
        out.write(buf); buf.clear()
out.write(buf)
