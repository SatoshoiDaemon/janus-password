"""Native vault chooser used by the desktop executable."""

import sys

from . import local


def main():
    from .run import main as run

    if len(sys.argv) > 1:
        return run()
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("Janus — Cofre local")
    root.geometry("460x260")
    root.minsize(400, 240)
    root.configure(padx=24, pady=24)
    ttk.Label(root, text="Janus", font=("Georgia", 26)).pack(anchor="w")
    ttk.Label(root, text="Escolha um cofre. Seus dados ficam neste computador.", wraplength=400).pack(
        anchor="w", pady=12
    )
    selected = tk.StringVar(value="default")
    picker = ttk.Combobox(root, textvariable=selected, values=local.list_vaults() or ["default"], state="normal")
    picker.pack(fill="x")
    ttk.Label(root, text="Para criar um cofre, digite um nome novo.").pack(anchor="w", pady=8)
    chosen = []

    def choose():
        try:
            local.vault_path(selected.get())
        except ValueError as exc:
            messagebox.showerror("Nome inválido", str(exc))
            return
        chosen.append(selected.get())
        root.destroy()

    ttk.Button(root, text="Abrir cofre", command=choose).pack(anchor="e", pady=12)
    root.mainloop()
    if chosen:
        try:
            run(["--vault", chosen[0]])
        except SystemExit as exc:
            if exc.code:
                messagebox.showerror(
                    "Janus", "Não foi possível iniciar. Verifique se este cofre ou a porta já está em uso."
                )


if __name__ == "__main__":
    main()
