# SPDX-License-Identifier: GPL-3.0-or-later
# Prototipo de investigación (spike). No es código de producción.
from smartcard.System import readers
from smartcard.scard import SCARD_CTL_CODE
c = readers()[0].createConnection(); c.connect()
f = c.control(SCARD_CTL_CODE(3400), [])
ioctl = int.from_bytes(bytes(f[2:6]), "big")
p = bytes(c.control(ioctl, []))
names = {1: "wLcdLayout", 2: "bEntryValidationCondition", 3: "bTimeOut2", 4: "wLcdMaxCharacters",
         5: "wLcdMaxLines", 6: "bMinPINSize", 7: "bMaxPINSize", 8: "sFirmwareID", 9: "bPPDUSupport",
         10: "dwMaxAPDUDataSize", 11: "wIdVendor", 12: "wIdProduct"}
i = 0
while i < len(p):
    t, l = p[i], p[i + 1]; v = p[i + 2:i + 2 + l]; i += 2 + l
    print(names.get(t, t), v.decode(errors="replace") if t == 8 else hex(int.from_bytes(v, "little")))
