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
VM_PATH = "./vm"

# Driver.exe не умеет компилировать эти тесты, поэтому я исключил их
SKIP_TESTS = {"test054", "test110", "test111"}

test_files = sorted(glob.glob(os.path.join(REGRESSION_DIR, "test*.lama")))
passed, failed, skipped = 0, 0, 0

print(f"=== Running regression tests ({len(test_files)} files) ===\n")

def clean_output(text):
    return " ".join(text.replace(">", "").split())

for test in test_files:
    base = os.path.splitext(test)[0]
    tname = os.path.basename(base)

    if tname in SKIP_TESTS:
        print(f"[{tname}] SKIPPED (not supported by Driver.exe)")
        skipped += 1
        continue

    bc_file = tname + ".bc"
    input_file = base + ".input" if os.path.exists(base + ".input") else None

    res_b = subprocess.run([DRIVER, "-I", RUNTIME_DIR, "-b", test], capture_output=True, text=True)
    if res_b.returncode != 0:
        print(f"[{tname}] FAILED TO COMPILE .bc\n{res_b.stderr}")
        failed += 1
        continue

    # Если есть отдельный .input файл - беру его, иначе пихаю в stdin нули
    stdin_data = "0\n" * 16
    if input_file:
        with open(input_file, "r") as f:
            stdin_data = f.read()

    ref_run = subprocess.run([DRIVER, "-I", RUNTIME_DIR, "-i", test], input=stdin_data, capture_output=True, text=True, timeout=15)
    expected = ref_run.stdout

    vm_run = subprocess.run([VM_PATH, bc_file], input=stdin_data, capture_output=True, text=True, timeout=15)
    actual = vm_run.stdout

    # Сверка. Учитываем, что тест может проверять легальную runtime-ошибку (как test803)
    if ref_run.returncode != 0:
        is_ok = (vm_run.returncode > 0)
    else:
        is_ok = (vm_run.returncode == 0) and (clean_output(actual) == clean_output(expected))

    if is_ok:
        passed += 1
        if ref_run.returncode != 0:
            print(f"[{tname}] OK (expected runtime error caught: {vm_run.stderr.strip()})")
        else:
            print(f"[{tname}] OK")
    else:
        failed += 1
        print(f"[{tname}] FAILED (Exit Code: {vm_run.returncode}, Ref Exit Code: {ref_run.returncode})")
        if vm_run.stderr.strip():
            print(f"  --- VM STDERR ---\n{vm_run.stderr.strip()}")
        print(f"  --- EXPECTED ---\n{expected.strip()}")
        print(f"  --- ACTUAL ---\n{actual.strip()}")
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
    ("Missing 'main' public symbol", struct.pack("<iii", 5, 0, 0) + b"test\x00\xff"),
    ("Invalid opcode 0xFE", struct.pack("<iii", 5, 0, 1) + struct.pack("<iiB", 0, 0, 0) + b"main\x00\xfe\xff"),
    ("Truncated CONST instruction", struct.pack("<iii", 5, 0, 1) + struct.pack("<iiB", 0, 0, 0) + b"main\x00\x10\x01"),
    ("Jump target out of bounds", struct.pack("<iii", 5, 0, 1) + struct.pack("<iiB", 0, 0, 0) + b"main\x00\x15" + struct.pack("<i", 9999)),
]

for desc, payload in bad_cases:
    with tempfile.NamedTemporaryFile(suffix=".bc", delete=False) as tf:
        tf.write(payload)
        tf_name = tf.name
    res = subprocess.run([VM_PATH, tf_name], capture_output=True, text=True)
    os.remove(tf_name)
    status = "OK" if res.returncode == 1 and "VM Error:" in res.stderr else "FAILED"
    print(f"[{status}] {desc}: {res.stderr.strip()}")


perf_files = sorted(glob.glob(os.path.join(PERF_DIR, "*.lama")))
if perf_files:
    print(f"\n=== Performance comparison ({len(perf_files)} tests) ===\n")
    print(f"{'Test':<15} | {'lamac -i (s)':<15} | {'My VM (s)':<15} | {'Speedup (vs -i)':<16}")
    print("-" * 85)
    
    for ptest in perf_files:
        base = os.path.splitext(ptest)[0]
        tname = os.path.basename(base)
        bc_file = tname + ".bc"

        res_b = subprocess.run([DRIVER, "-I", RUNTIME_DIR, "-b", ptest], capture_output=True, text=True)
        if res_b.returncode != 0:
            continue

        t0 = time.perf_counter()
        subprocess.run([DRIVER, "-I", RUNTIME_DIR, "-i", ptest], input="", capture_output=True, text=True)
        t_ref_i = time.perf_counter() - t0

        t0 = time.perf_counter()
        subprocess.run([VM_PATH, bc_file], input="", capture_output=True, text=True)
        t_vm = time.perf_counter() - t0

        speedup = t_ref_i / t_vm if t_vm > 0 else 0.0
        speedup_str = f"{speedup:.2f}x"
        print(f"{tname:<15} | {t_ref_i:<15.4f} | {t_vm:<15.4f} | {speedup_str:<10}")

        if os.path.exists(bc_file):
            os.remove(bc_file)