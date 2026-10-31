"""Pure-Python SM4 cipher; SM4Key-compatible CBC API, no padding."""
_MASK=0xffffffff
_FK=(0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc)
_CK=tuple(int(x,16) for x in """00070e15 1c232a31 383f464d 545b6269 70777e85 8c939aa1 a8afb6bd c4cbd2d9 e0e7eef5 fc030a11 181f262d 343b4249 50575e65 6c737a81 888f969d a4abb2b9 c0c7ced5 dce3eaf1 f8ff060d 141b2229 30373e45 4c535a61 686f767d 848b9299 a0a7aeb5 bcc3cad1 d8dfe6ed f4fb0209 10171e25 2c333a41 484f565d 646b7279""".split())
_SBOX=bytes.fromhex("""d690e9fecce13db716b614c228fb2c05 2b679a762abe04c3aa44132649860699 9c4250f491ef987a33540b43edcfac62 e4b31ca9c908e89580df94fa758f3fa6 4707a7fcf37317ba83593c19e6854fa8 686b81b27164da8bf8eb0f4b70569d35 1e240e5e6358d1a225227c3b01217887 d40046579fd327524c3602e7a0c4c89e eabf8ad240c738b5a3f7f2cef96115a1 e0ae5da49b341a55ad933230f58cb1e3 1df6e22e8266ca60c02923ab0d534e6f d5db3745defd8e2f03ff6a726d6c5b51 8d1baf92bbddbc7f11d95c411f105ad8 0ac13188a5cd7bbd2d74d012b8e5b4b0 8969974a0c96777e65b9f109c56ec684 18f07dec3adc4d2079ee5f3ed7cb3948""")
def _rol(x,n): return ((x<<n)|(x>>(32-n)))&_MASK
def _tau(x): return (_SBOX[x>>24]<<24)|(_SBOX[(x>>16)&255]<<16)|(_SBOX[(x>>8)&255]<<8)|_SBOX[x&255]
def _rt(x):
 b=_tau(x); return b^_rol(b,2)^_rol(b,10)^_rol(b,18)^_rol(b,24)
def _kt(x):
 b=_tau(x); return b^_rol(b,13)^_rol(b,23)
class SM4Key:
 def __init__(self,key):
  key=bytes(key)
  if len(key)!=16: raise ValueError("SM4 key must be exactly 16 bytes")
  k=[int.from_bytes(key[i:i+4],"big")^_FK[i//4] for i in range(0,16,4)]; rk=[]
  for i in range(32):
   v=k[i]^_kt(k[i+1]^k[i+2]^k[i+3]^_CK[i]); k.append(v); rk.append(v)
  self._rk=tuple(rk)
 def _block(self,b,dec=False):
  if len(b)!=16: raise ValueError("SM4 block must be 16 bytes")
  x=[int.from_bytes(b[i:i+4],"big") for i in range(0,16,4)]
  for r in (reversed(self._rk) if dec else self._rk): x.append(x[-4]^_rt(x[-3]^x[-2]^x[-1]^r))
  return b"".join(v.to_bytes(4,"big") for v in reversed(x[-4:]))
 def encrypt(self,data,initial=None): return self._cbc(data,initial,False)
 def decrypt(self,data,initial=None): return self._cbc(data,initial,True)
 def _cbc(self,data,initial,dec):
  data=bytes(data)
  if len(data)%16: raise ValueError("SM4-CBC input length must be a multiple of 16")
  prev=bytes(initial) if initial is not None else bytes(16)
  if len(prev)!=16: raise ValueError("SM4-CBC IV must be exactly 16 bytes")
  out=bytearray()
  for i in range(0,len(data),16):
   b=data[i:i+16]
   if dec:
    q=self._block(b,True); out.extend(a^c for a,c in zip(q,prev)); prev=b
   else:
    q=self._block(bytes(a^c for a,c in zip(b,prev))); out.extend(q); prev=q
  return bytes(out)
