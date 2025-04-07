from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QFileDialog, QMessageBox, QHBoxLayout
import re

# Tabela de syscalls Linux (parcial para exemplo)
LINUX_SYSCALLS = {
    0: "read", 1: "write", 2: "open", 3: "close", 11: "execve", 60: "exit", 39: "getpid"
}

# Tabela de syscalls Windows (parcial para exemplo)
WINDOWS_SYSCALLS = {
    0x18: "NtAllocateVirtualMemory", 0x25: "NtCreateThread", 0x3f: "NtProtectVirtualMemory"
}

def register(app):
    tab = QWidget()
    layout = QVBoxLayout()

    layout.addWidget(QLabel("Syscall Analyzer - Shellcode Analysis"))

    shellcode_input = QTextEdit()
    shellcode_input.setPlaceholderText("Paste your shellcode here (e.g. \\x90\\x90...)")
    layout.addWidget(shellcode_input)

    result_output = QTextEdit()
    result_output.setReadOnly(True)
    layout.addWidget(result_output)

    def get_shellcode_bytes():
        raw = shellcode_input.toPlainText().strip()
        if not raw:
            return b'', "No shellcode provided."

        try:
            cleaned = raw.replace('"', '').replace("'", "").replace(';', '')
            cleaned = re.sub(r"[\n\r\t, ]", "", cleaned)

            if "\\x" in cleaned:
                hex_str = cleaned.replace("\\x", "")
            else:
                hex_str = re.sub(r"[^0-9a-fA-F]", "", cleaned)

            return bytes.fromhex(hex_str), ""
        except Exception as e:
            return b'', f"[!] Error parsing shellcode: {str(e)}"

    def load_bin():
        path, _ = QFileDialog.getOpenFileName(tab, "Load Shellcode .bin", "", "Binary Files (*.bin)")
        if path:
            try:
                with open(path, "rb") as f:
                    data = f.read()
                    hexed = ''.join(f'\\x{b:02x}' for b in data)
                    shellcode_input.setPlainText(hexed)
            except Exception as e:
                QMessageBox.critical(tab, "Error", str(e))

    def analyze_syscalls():
        result_output.clear()
        data, err = get_shellcode_bytes()
        if err:
            result_output.setText(err)
            return

        result_output.append(f"[+] Shellcode length: {len(data)} bytes")

        arch = "Unknown"
        if b"\x0f\x05" in data:
            arch = "x64"
        elif b"\xcd\x80" in data or b"\x0f\x34" in data:
            arch = "x86"

        result_output.append(f"[+] Architecture: {arch}")

        syscalls_found = []

        for i in range(len(data) - 4):
            opcode = data[i:i+2]

            if arch == "x86" and opcode == b"\xcd\x80":
                syscall_num = data[i-2] if i >= 2 else None
                call = LINUX_SYSCALLS.get(syscall_num, "Unknown syscall")
                syscalls_found.append(f"[*] syscall int 0x80 (eax={syscall_num}) → {call}")

            elif arch == "x64" and opcode == b"\x0f\x05":
                # tentativa de detectar syscall antes: mov rax, xx
                if i >= 7 and data[i-7:i-2][:2] == b"\x48\xc7":
                    syscall_num = data[i-3]
                    call = LINUX_SYSCALLS.get(syscall_num, "Unknown syscall")
                    syscalls_found.append(f"[*] syscall syscall (rax={syscall_num}) → {call}")
                else:
                    syscalls_found.append("[*] syscall syscall (rax unknown)")

            elif arch == "x86" and data[i:i+2] == b"\x0f\x34":
                syscalls_found.append("[*] sysenter (Windows x86)")

        if syscalls_found:
            result_output.append("\n".join(syscalls_found))
        else:
            result_output.append("[*] No syscalls found.")

    # Botões
    btn_layout = QHBoxLayout()
    analyze_btn = QPushButton("Analyze Syscalls")
    analyze_btn.clicked.connect(analyze_syscalls)
    load_btn = QPushButton("Load .bin File")
    load_btn.clicked.connect(load_bin)
    btn_layout.addWidget(load_btn)
    btn_layout.addWidget(analyze_btn)

    layout.addLayout(btn_layout)
    tab.setLayout(layout)
    app.tabs.addTab(tab, "Syscall Analyzer")
