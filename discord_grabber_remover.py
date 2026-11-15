"""Interface gráfica e linha de comando do Discord Grabber Remover."""
import argparse
import json
import os
from pathlib import Path
import queue
import tempfile
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scanner import discover_roots, scan, quarantine, restore

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Discord Grabber Remover")
        self.geometry("900x590")
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.result = None
        self.roots = discover_roots()
        self.quarantine_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "DiscordGrabberRemover" / "quarantine"
        top = ttk.Frame(self, padding=10); top.pack(fill="x")
        self.scan_button = ttk.Button(top, text="Verificar Discord", command=self.start); self.scan_button.pack(side="left")
        self.cancel_button = ttk.Button(top, text="Cancelar", command=self.stop.set, state="disabled"); self.cancel_button.pack(side="left", padx=5)
        ttk.Button(top, text="Escolher pasta", command=self.choose).pack(side="left", padx=5)
        ttk.Button(top, text="Exportar JSON", command=self.export).pack(side="left", padx=5)
        ttk.Button(top, text="Restaurar quarentena", command=self.restore_file).pack(side="right")
        self.status = tk.StringVar(value="Pronto. A análise não altera arquivos.")
        ttk.Label(self, textvariable=self.status, padding=10).pack(fill="x")
        self.table = ttk.Treeview(self, columns=("risk", "path", "reasons"), show="headings", selectmode="browse")
        for col, label, width in [("risk", "Risco", 80), ("path", "Arquivo", 480), ("reasons", "Indícios", 300)]:
            self.table.heading(col, text=label); self.table.column(col, width=width)
        self.table.pack(fill="both", expand=True, padx=10)
        self.details = tk.Text(self, height=7, wrap="word"); self.details.pack(fill="x", padx=10, pady=8)
        self.table.bind("<<TreeviewSelect>>", self.show_details)
        bottom = ttk.Frame(self, padding=10); bottom.pack(fill="x")
        self.remove_button = ttk.Button(bottom, text="Colocar selecionado em quarentena", command=self.remove, state="disabled"); self.remove_button.pack(side="left")
        ttk.Label(bottom, text="Indícios exigem revisão; a ausência deles não garante segurança.").pack(side="right")
        self.after(100, self.poll)
    def choose(self):
        path = filedialog.askdirectory(title="Selecione a pasta Discord (contendo app-*)")
        if path:
            self.roots = [Path(path)]; self.status.set(f"Pasta selecionada: {path}")
    def start(self):
        if not self.roots:
            messagebox.showinfo("Discord", "Nenhuma instalação encontrada. Use Escolher pasta."); return
        self.stop.clear(); self.result = None
        self.table.delete(*self.table.get_children()); self.details.delete("1.0", "end")
        self.scan_button.config(state="disabled"); self.cancel_button.config(state="normal"); self.remove_button.config(state="disabled")
        self.status.set("Verificando…")
        def worker():
            try:
                result = scan(self.roots, self.stop.is_set, lambda path: self.events.put(("progress", path)))
                self.events.put(("done", result))
            except Exception as e:
                self.events.put(("error", str(e)))
        threading.Thread(target=worker, daemon=True).start()
    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "progress": self.status.set("Verificando: " + value)
                elif kind == "done":
                    self.result = value
                    for i, finding in enumerate(value.findings): self.table.insert("", "end", iid=str(i), values=(finding.risk, finding.path, ", ".join(finding.reasons)))
                    self.status.set(f"{'Cancelada' if value.cancelled else 'Concluída'}: {value.files_scanned} arquivos, {len(value.findings)} achados, {len(value.errors)} avisos.")
                    if value.errors: self.details.insert("end", "Avisos:\n" + "\n".join(value.errors))
                    self.scan_button.config(state="normal"); self.cancel_button.config(state="disabled")
                elif kind == "error":
                    self.status.set("Falha na varredura: " + value); self.scan_button.config(state="normal"); self.cancel_button.config(state="disabled")
        except queue.Empty: pass
        self.after(100, self.poll)
    def show_details(self, event=None):
        selected = self.table.selection()
        if not selected or not self.result: return
        f = self.result.findings[int(selected[0])]
        self.details.delete("1.0", "end"); self.details.insert("end", f"Arquivo: {f.path}\nSHA-256: {f.sha256}\nIndícios: {', '.join(f.reasons)}\nConfira o arquivo antes de colocá-lo em quarentena. O Discord pode precisar ser reinstalado.")
        self.remove_button.config(state="normal")
    def remove(self):
        selected = self.table.selection()
        if not selected or not self.result: return
        f = self.result.findings[int(selected[0])]
        if not messagebox.askyesno("Confirmar quarentena", f"Feche o Discord antes de continuar. Mover este arquivo pode impedir o aplicativo de abrir.\n\n{f.path}\n\nDeseja continuar?"): return
        try:
            metadata = quarantine(f, self.quarantine_dir)
            self.table.delete(selected[0]); self.remove_button.config(state="disabled")
            messagebox.showinfo("Quarentena", f"Cópia preservada em:\n{metadata}\n\nReinstale o Discord pela fonte oficial se necessário.")
        except (OSError, ValueError) as e: messagebox.showerror("Erro", str(e))
    def export(self):
        if not self.result: messagebox.showinfo("Relatório", "Faça uma varredura primeiro."); return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            try: Path(path).write_text(json.dumps(self.result.as_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError as e: messagebox.showerror("Erro", str(e))
    def restore_file(self):
        path = filedialog.askopenfilename(title="Selecione o arquivo JSON da quarentena", initialdir=str(self.quarantine_dir), filetypes=[("JSON", "*.json")])
        if path:
            try: messagebox.showinfo("Restaurado", f"Arquivo restaurado: {restore(path)}")
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as e: messagebox.showerror("Erro", str(e))

def main():
    parser = argparse.ArgumentParser(description="Analisa scripts do módulo Discord desktop core.")
    parser.add_argument("--scan", action="store_true", help="executa análise em linha de comando")
    parser.add_argument("--path", type=Path, help="pasta Discord contendo app-*")
    parser.add_argument("--demo", action="store_true", help="simula um arquivo suspeito em pasta temporária")
    args = parser.parse_args()
    if args.demo:
        with tempfile.TemporaryDirectory(prefix="discord-grabber-demo-") as temporary:
            root = Path(temporary) / "Discord" / "app-demo" / "modules" / "discord_desktop_core-demo" / "discord_desktop_core"
            root.mkdir(parents=True)
            (root / "demo.js").write_text(
                "// SIMULAÇÃO INOFENSIVA: nenhum token real\n"
                "const token = localStorage.getItem('token');\n"
                "fetch('https://discord.com/api/webhooks/000000000000000000/demo');\n",
                encoding="utf-8",
            )
            result = scan([root.parents[3]])
            print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
            return 0 if result.findings else 1
    if args.scan:
        roots = [args.path] if args.path else discover_roots()
        result = scan(roots)
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        return 2 if not roots or result.errors else 0
    App().mainloop()
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
