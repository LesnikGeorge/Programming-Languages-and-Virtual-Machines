import os
import subprocess
import glob
import time
import struct
import tempfile

LAMA_DIR = os.path.expanduser("~/Documents/YP_VM/Lama")
DRIVER = os.path.join(LAMA_DIR, "_build/default/src/Driver.exe")
RUNTIME_DIR = os.path.join(LAMA_DIR, "runtime")
REGRESSION_DIR = os.path.join(LAMA_DIR, "regression")
PERF_DIR = os.path.join(LAMA_DIR, "performance")
ANALYZER_PATH = "./analyzer"

# Driver.exe не умеет компилировать эти тесты, поэтому я исключил их
SKIP_TESTS = {"test054", "test110", "test111"}

test_files = sorted(glob.glob(os.path.join(REGRESSION_DIR, "test*.lama")))
passed, failed, skipped = 0, 0, 0

print(f"=== Running regression (smoke) tests ({len(test_files)} files) ===\n")

for test in test_files:
    base = os.path.splitext(test)[0]
    tname = os.path.basename(base)

    if tname in SKIP_TESTS:
        print(f"[{tname}] SKIPPED (not supported by Driver.exe)")
        skipped += 1
        continue

    bc_file = tname + ".bc"

    res_b = subprocess.run([DRIVER, "-I", RUNTIME_DIR, "-b", test], capture_output=True, text=True)
    if res_b.returncode != 0:
        print(f"[{tname}] FAILED TO COMPILE .bc\n{res_b.stderr}")
        failed += 1
        continue

    # Для смок-теста достаточно убедиться, что парсер не словил сегфолт и отдал 0
    an_run = subprocess.run([ANALYZER_PATH, bc_file], capture_output=True, text=True, timeout=5)
    is_ok = (an_run.returncode == 0)

    if is_ok:
        passed += 1
        print(f"[{tname}] OK")
    else:
        failed += 1
        print(f"[{tname}] FAILED (Exit Code: {an_run.returncode})")
        if an_run.stderr.strip():
            print(f"  --- ANALYZER STDERR ---\n{an_run.stderr.strip()}")
        print("-" * 50)

    if os.path.exists(bc_file):
        os.remove(bc_file)

print(f"\n==========================================")
print(f"SUMMARY: Passed: {passed}, Failed: {failed}, Skipped: {skipped}")


print(f"\n=== Testing corrupted input files diagnostics ===\n")

bad_cases = [
    ("File too short (< 12 bytes)", b"\x01\x02\x03"),
    ("Negative header fields", struct.pack("<iii", -5, 0, 0)),
    ("Tables size exceeds file size", struct.pack("<iii", 1000, 0, 10)),
    ("Non-null-terminated string table", struct.pack("<iii", 3, 0, 0) + b"abc\xff"),
    ("Truncated instruction (CONST)", struct.pack("<iii", 5, 0, 1) + struct.pack("<iiB", 0, 0, 0) + b"main\x00\x10\x01"),
    ("Jump target out of bounds", struct.pack("<iii", 5, 0, 1) + struct.pack("<iiB", 0, 0, 0) + b"main\x00\x15" + struct.pack("<i", 9999)),
]

for desc, payload in bad_cases:
    with tempfile.NamedTemporaryFile(suffix=".bc", delete=False) as tf:
        tf.write(payload)
        tf_name = tf.name
        
    res = subprocess.run([ANALYZER_PATH, tf_name], capture_output=True, text=True)
    os.remove(tf_name)
    
    # Должен упасть с ненулевым кодом и отдать диагностику
    status = "OK" if res.returncode != 0 and "VM Error:" in res.stderr else "FAILED"
    print(f"[{status}] {desc}: {res.stderr.strip()}")


perf_files = sorted(glob.glob(os.path.join(PERF_DIR, "*.lama")))
if perf_files:
    print(f"\n=== Performance Tests Target Analysis ({len(perf_files)} files) ===\n")
    
    for ptest in perf_files:
        base = os.path.splitext(ptest)[0]
        tname = os.path.basename(base)
        bc_file = tname + ".bc"

        res_b = subprocess.run([DRIVER, "-I", RUNTIME_DIR, "-b", ptest], capture_output=True, text=True)
        if res_b.returncode != 0:
            print(f"[{tname}] Compilation failed!")
            continue

        t0 = time.perf_counter()
        an_run = subprocess.run([ANALYZER_PATH, bc_file], capture_output=True, text=True)
        t_an = time.perf_counter() - t0

        if an_run.returncode == 0:
            print(f"[{tname}] Analyzed in {t_an:.4f} seconds. N-grams output:\n")
            print(an_run.stdout)
            print("-" * 50)
        else:
            print(f"[{tname}] Analyzer failed with code {an_run.returncode}")
            if an_run.stderr.strip():
                print(f"  --- STDERR ---\n{an_run.stderr.strip()}")
            print("-" * 50)

        if os.path.exists(bc_file):
            os.remove(bc_file)
else:
    print("\nNo performance tests found in", PERF_DIR)