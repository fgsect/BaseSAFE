# goes into /errc/
import os
import subprocess
import secrets

total_len = 0
total_cov_PCCH = 0
total_cov_BCCH = 0
total_cov_CCCH = 0
total_cov_DCCH = 0
decoder = {"PCCH":0, "BCCH_DL_SCH":0, "DL_CCCH":0, "DL_DCCH":0}

for i in range(30):
    length = 32 + secrets.randbelow(10)
    total_len += length
    os.system(f"cat /dev/urandom | head --bytes {length + 1} > ../data/noise.raw")
    for d in decoder:
        x = subprocess.check_output([f"../../AFLplusplus/afl-showmap -m none -o ./map -- target/release/errc_fuzz ../data/noise.raw {d}"], stderr=subprocess.STDOUT, shell=True)
        cov = x.split(b'total values ')[1].split(b')')[0]
        decoder[d] = decoder[d] + int(cov.decode())
    print(cov)

avg_len = total_len // 30
print(avg_len)
for d in decoder:
    print(f"{d}: {decoder[d] // 30}")
