"""Dump live BagMRU/Bags structure (handles regipy hex-string binaries)."""
import os, struct, subprocess, tempfile

SID = "S-1-5-21-738669000-806746341-1809076488-1002"
tmp = os.path.join(tempfile.gettempdir(), "ntuser_shellbag.hve")
rc = subprocess.run(["reg", "save", rf"HKU\{SID}", tmp, "/y"], capture_output=True)
print("reg save rc:", rc.returncode)
if rc.returncode != 0:
    subprocess.run(["reg", "save", "HKCU", tmp, "/y"], capture_output=True)

from regipy.registry import RegistryHive
hive = RegistryHive(tmp)


def blob(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if (isinstance(value, str) and value
            and all(c in "0123456789abcdefABCDEF" for c in value)
            and len(value) % 2 == 0):
        return bytes.fromhex(value)
    return None


for base in (r"\Software\Microsoft\Windows\Shell",
             r"\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell"):
    print(f"\n================ {base} ================")
    try:
        key = hive.get_key(base + r"\BagMRU")
    except Exception as e:
        print("missing:", e)
        continue
    print("--- BagMRU values ---")
    raws = {}
    for v in key.iter_values():
        raw = blob(v.value)
        if raw is not None:
            raws[v.name] = raw
            print(f"{v.name:<12} hex len={len(raw):<5} {raw.hex()[:120]}")
        else:
            print(f"{v.name:<12} {v.value!r}")

    print("--- node parse: [items...][child-ids] ---")
    for name, raw in sorted(raws.items(), key=lambda kv: (len(kv[0]), kv[0])):
        if not name.isdigit() and name != "Node":
            continue
        items, off = [], 0
        while off + 2 <= len(raw):
            size = struct.unpack_from("<H", raw, off)[0]
            if size < 4 or off + size > len(raw):
                break
            items.append(raw[off:off + size])
            off += size
        tail = raw[off:]
        ids = [struct.unpack_from("<H", tail, i)[0]
               for i in range(0, len(tail) - 1, 2)]
        print(f"node {name}: {len(items)} items, tail={tail.hex()}, ids={ids}")
        for it in items:
            typ = it[2] if len(it) > 2 else -1
            print(f"   size={len(it):<3} type=0x{typ:02x} body={it[2:].hex()[:96]}")

    try:
        bags = hive.get_key(base + r"\Bags")
    except Exception as e:
        print("bags missing:", e)
        continue
    subs = list(bags.iter_subkeys())
    nums = sorted(int(s.name) for s in subs if s.name.isdigit())
    print(f"--- Bags: {len(subs)} subkeys, numeric {nums[:30]}{'...' if len(nums) > 30 else ''} ---")
    for s in subs[:10]:
        kids = [k.name for k in s.iter_subkeys()]
        print(f"  Bags\\{s.name:<5} lw={s.header.last_modified} kids={kids[:4]}")

os.remove(tmp)
