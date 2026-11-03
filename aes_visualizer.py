"""AES-128 Runden-Visualisierung (tkinter).

Zeigt Schritt fuer Schritt, wie sich die 4x4-State-Matrix in jeder Runde veraendert
(SubBytes, ShiftRows, MixColumns, AddRoundKey) und welcher Rundenschluessel
aus dem Key-Schedule verwendet wird.

Start:  python aes_visualizer.py
Test:   python aes_visualizer.py --test
"""
import sys


# ---------------------------------------------------------------- AES-Logik
def xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r


def make_sbox():
    sbox = []
    for x in range(256):
        inv = 0
        if x:
            inv = next(y for y in range(1, 256) if gmul(x, y) == 1)
        s = inv
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox.append(s ^ 0x63)
    return sbox


SBOX = make_sbox()


def bytes_to_state(b):
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]  # spaltenweise


def state_to_bytes(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def key_expansion(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return w


def round_key(w, rnd):
    return [[w[4 * rnd + c][r] for c in range(4)] for r in range(4)]


def sub_bytes(s):
    return [[SBOX[x] for x in row] for row in s]


def shift_rows(s):
    return [row[i:] + row[:i] for i, row in enumerate(s)]


def mix_columns(s):
    m = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= gmul(m[r][k], s[k][c])
            out[r][c] = v
    return out


def add_round_key(s, k):
    return [[s[r][c] ^ k[r][c] for c in range(4)] for r in range(4)]


def build_steps(plain, key):
    """Liefert eine Liste von Schritten: dict(title, info, state, prev, key, round)."""
    w = key_expansion(key)
    steps = []
    state = bytes_to_state(plain)
    steps.append(dict(title="Eingabe (Klartext)", round=0, prev=None, state=state, key=None,
                      info="Die 16 Klartext-Bytes werden spaltenweise in die 4x4-Matrix geschrieben."))
    k0 = round_key(w, 0)
    prev, state = state, add_round_key(state, k0)
    steps.append(dict(title="Runde 0 - AddRoundKey", round=0, prev=prev, state=state, key=k0,
                      info="State XOR Rundenschluessel 0 (= der urspruengliche Schluessel)."))
    for rnd in range(1, 11):
        prev, state = state, sub_bytes(state)
        steps.append(dict(title=f"Runde {rnd} - SubBytes", round=rnd, prev=prev, state=state, key=None,
                          info="Jedes Byte wird durch die S-Box ersetzt."))
        prev, state = state, shift_rows(state)
        steps.append(dict(title=f"Runde {rnd} - ShiftRows", round=rnd, prev=prev, state=state, key=None,
                          info="Zeile 0: keine Verschiebung, Zeile 1: 1 links, Zeile 2: 2 links, Zeile 3: 3 links."))
        if rnd < 10:
            prev, state = state, mix_columns(state)
            steps.append(dict(title=f"Runde {rnd} - MixColumns", round=rnd, prev=prev, state=state, key=None,
                              info="Jede Spalte wird im GF(2^8) mit der festen Matrix [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2] multipliziert."))
        k = round_key(w, rnd)
        first = w[4 * rnd]
        prev, state = state, add_round_key(state, k)
        steps.append(dict(title=f"Runde {rnd} - AddRoundKey", round=rnd, prev=prev, state=state, key=k,
                          info=f"State XOR Rundenschluessel {rnd}. "
                               f"Erstes Wort w{4 * rnd} = {bytes(first).hex()}."
                               + (" (letzte Runde: kein MixColumns)" if rnd == 10 else "")))
    return steps, w


def encrypt(plain, key):
    steps, _ = build_steps(plain, key)
    return state_to_bytes(steps[-1]["state"])


def self_test():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert encrypt(pt, key).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert encrypt(pt, key).hex() == "3925841d02dc09fb dc118597196a0b32".replace(" ", "")
    print("OK - AES-Implementierung stimmt mit FIPS-197 ueberein.")


def pad(b):
    """PKCS#7-Padding auf einen 16-Byte-Block (nur fuer Eingaben < 16 Bytes)."""
    n = 16 - len(b)
    return b + bytes([n]) * n


def unpad(b):
    n = b[-1]
    if 1 <= n <= 16 and b.endswith(bytes([n]) * n):
        return b[:-n]
    return b


def rcon_value(n):
    r = 1
    for _ in range(n - 1):
        r = xtime(r)
    return r


def formula_text(st, w):
    """Formel des aktuellen Schritts mit den konkreten Werten."""
    h = lambda v: f"{v:02x}"
    hw = lambda word: bytes(word).hex()
    prev, cur, rnd = st["prev"], st["state"], st["round"]
    op = st["title"].split(" - ")[-1]
    L = []
    if prev is None:
        L.append("Eingabe:   s[r][c] = Byte[r + 4·c]     (die 16 Bytes werden spaltenweise eingetragen)")
    elif op == "SubBytes":
        L.append("SubBytes:   s'[r][c] = S( s[r][c] )     S = S-Box (Inversion in GF(2^8) + affine Abbildung)")
        for r in range(4):
            L.append(f"  Zeile {r}:  " + "   ".join(f"S({h(prev[r][c])})={h(cur[r][c])}" for c in range(4)))
    elif op == "ShiftRows":
        L.append("ShiftRows:  s'[r][c] = s[r][(c + r) mod 4]     Zeile r wird um r Positionen nach links rotiert")
        for r in range(4):
            L.append(f"  Zeile {r}:  [{' '.join(h(x) for x in prev[r])}]  →  [{' '.join(h(x) for x in cur[r])}]"
                     f"   (um {r} nach links)")
    elif op == "MixColumns":
        m = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        L.append("MixColumns: s'[r][c] = M[r][0]·s[0][c] ⊕ M[r][1]·s[1][c] ⊕ M[r][2]·s[2][c] ⊕ M[r][3]·s[3][c]"
                 "     (Multiplikation in GF(2^8))")
        for r in range(4):
            terms = " ⊕ ".join(f"{m[r][i]:02x}·{h(prev[i][0])}" for i in range(4))
            prods = " ⊕ ".join(h(gmul(m[r][i], prev[i][0])) for i in range(4))
            L.append(f"  s'[{r}][0] = {terms} = {prods} = {h(cur[r][0])}")
        L.append("  (gezeigt fuer Spalte 0 - die Spalten 1 bis 3 werden genauso berechnet)")
    else:
        k = st["key"]
        L.append("AddRoundKey: s'[r][c] = s[r][c] ⊕ k[r][c]     (⊕ = XOR)")
        for r in range(4):
            L.append(f"  Zeile {r}:  " + "   ".join(f"{h(prev[r][c])}⊕{h(k[r][c])}={h(cur[r][c])}" for c in range(4)))
        if rnd == 0:
            L.append("Rundenschluessel 0 = Originalschluessel (w0..w3 = Key-Bytes, spaltenweise).")
        else:
            i = 4 * rnd
            rot = w[i - 1][1:] + w[i - 1][:1]
            sub = [SBOX[x] for x in rot]
            rc = rcon_value(rnd)
            t = sub[:]
            t[0] ^= rc
            L.append(f"Key-Schedule:  w{i} = w{i - 4} ⊕ SubWord(RotWord(w{i - 1})) ⊕ Rcon[{rnd}]"
                     f"     w{i + 1} = w{i - 3} ⊕ w{i}   w{i + 2} = w{i - 2} ⊕ w{i + 1}   w{i + 3} = w{i - 1} ⊕ w{i + 2}")
            L.append(f"  w{i - 1}={hw(w[i - 1])}  RotWord={hw(rot)}  SubWord={hw(sub)}  Rcon={rc:02x}000000"
                     f"  →  w{i - 4}={hw(w[i - 4])} ⊕ {hw(t)} = w{i}={hw(w[i])}")
    return "\n".join(L)


# ---------------------------------------------------------------------- GUI
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    BG, FG = "#f5f5f7", "#1e1e2e"
    CELL, CHG, KEYC = "#e0e4ec", "#ffd966", "#9cc5f5"

    root = tk.Tk()
    root.title("AES-128 Runden-Visualisierung")
    root.configure(bg=BG)
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    w, h = min(1000, sw - 40), min(920, sh - 100)
    root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 2 - 20)}")
    root.minsize(320, 240)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton", padding=6)

    import tkinter.font as tkfont
    FONTS = {}   # name -> (Font, Basisgroesse)

    def mkfont(name, family, size, weight="normal", slant="roman"):
        f = tkfont.Font(family=family, size=-round(size * 4 / 3), weight=weight, slant=slant)
        FONTS[name] = (f, size)
        return f

    mono = mkfont("mono", "Consolas", 16, "bold")
    small = mkfont("small", "Consolas", 10)
    head = mkfont("head", "Segoe UI", 12, "bold")
    f_made = mkfont("made", "Segoe UI", 8, slant="italic")
    f_bytes = mkfont("bytes", "Consolas", 9)
    f_title = mkfont("title", "Segoe UI", 15, "bold")
    f_arrow = mkfont("arrow", "Segoe UI", 28)
    f_out = mkfont("out", "Consolas", 11, "bold")
    f_ui = mkfont("ui", "Segoe UI", 9)
    for nm in ("TkDefaultFont", "TkTextFont"):
        FONTS[nm] = (tkfont.nametofont(nm), 9)
    style.configure("TButton", font=f_ui)

    # --- Steuerleiste immer unten sichtbar, Inhalt scrollbar
    bar = tk.Frame(root, bg=BG)
    bar.pack(side="bottom", pady=(4, 8))
    page = tk.Frame(root, bg=BG)
    page.pack(side="top", fill="both", expand=True)

    # --- Eingaben
    tk.Label(page, text="made by yama", bg=BG, fg="#a0a4b0",
             font=f_made).pack(anchor="e", padx=12, pady=(6, 0))
    top = tk.Frame(page, bg=BG)
    top.pack(fill="x", padx=12, pady=(12, 4))
    mode_var = tk.StringVar(value="text")
    pt_label = tk.Label(top, bg=BG, fg=FG)
    pt_label.grid(row=0, column=0, sticky="w")
    pt_var = tk.StringVar(value="hallo")
    tk.Entry(top, textvariable=pt_var, width=38, font=small).grid(row=0, column=1, padx=6, pady=2)
    key_label = tk.Label(top, bg=BG, fg=FG)
    key_label.grid(row=1, column=0, sticky="w")
    key_var = tk.StringVar(value="GEHEIMSCHLUESSEL")
    tk.Entry(top, textvariable=key_var, width=38, font=small).grid(row=1, column=1, padx=6, pady=2)
    modes = tk.Frame(top, bg=BG)
    modes.grid(row=0, column=2, rowspan=2, padx=12)
    bytes_var = tk.StringVar()
    tk.Label(top, textvariable=bytes_var, bg=BG, fg="#555566", font=f_bytes,
             justify="left").grid(row=2, column=0, columnspan=3, sticky="w", pady=(2, 0))

    def set_labels():
        if mode_var.get() == "text":
            pt_label.config(text="Klartext (Text):")
            key_label.config(text="Schluessel (genau 16 Zeichen):")
        else:
            pt_label.config(text="Klartext (32 Hex):")
            key_label.config(text="Schluessel (32 Hex):")

    def on_mode():
        # Eingaben beim Umschalten zwischen Text und Hex umrechnen
        try:
            if mode_var.get() == "hex":
                pt_var.set(pad(pt_var.get().encode("utf-8")).hex())
                key_var.set(key_var.get().encode("utf-8").hex())
            else:
                pt_var.set(unpad(bytes.fromhex(pt_var.get().strip())).decode("utf-8"))
                key_var.set(bytes.fromhex(key_var.get().strip()).decode("utf-8"))
        except ValueError:
            pass
        set_labels()

    tk.Radiobutton(modes, text="Text", variable=mode_var, value="text", command=on_mode,
                   bg=BG, fg=FG, selectcolor=BG, activebackground=BG).pack(anchor="w")
    tk.Radiobutton(modes, text="Hex", variable=mode_var, value="hex", command=on_mode,
                   bg=BG, fg=FG, selectcolor=BG, activebackground=BG).pack(anchor="w")
    set_labels()

    body = tk.Frame(page, bg=BG)
    body.pack(fill="both", expand=True)
    left = tk.Frame(body, bg=BG)
    left.pack(side="left", fill="both", expand=True)

    title_var = tk.StringVar()
    tk.Label(left, textvariable=title_var, bg=BG, fg=FG, font=f_title).pack(pady=(8, 0))
    info_var = tk.StringVar()
    info_lbl = tk.Label(left, textvariable=info_var, bg=BG, fg="#555566", wraplength=700, justify="center")
    info_lbl.pack(pady=(0, 6))

    # --- Matrizen
    mid = tk.Frame(left, bg=BG)
    mid.pack(pady=4)

    def make_matrix(parent, caption):
        f = tk.Frame(parent, bg=BG)
        tk.Label(f, text=caption, bg=BG, fg=FG, font=head).grid(row=0, column=0, columnspan=4, pady=(0, 4))
        cells = []
        for r in range(4):
            row = []
            for c in range(4):
                lb = tk.Label(f, text="--", width=4, height=2, font=mono, bg=CELL, fg=FG, relief="flat")
                lb.grid(row=r + 1, column=c, padx=2, pady=2)
                row.append(lb)
            cells.append(row)
        return f, cells

    f_prev, prev_cells = make_matrix(mid, "Vorher")
    f_prev.grid(row=0, column=0, padx=14)
    tk.Label(mid, text="➜", bg=BG, fg=FG, font=f_arrow).grid(row=0, column=1)
    f_cur, cur_cells = make_matrix(mid, "State (nachher)")
    f_cur.grid(row=0, column=2, padx=14)
    tk.Label(mid, text="⊕", bg=BG, fg=FG, font=f_arrow).grid(row=0, column=3)
    f_key, key_cells = make_matrix(mid, "Rundenschluessel")
    f_key.grid(row=0, column=4, padx=14)

    # --- Formel des aktuellen Schritts
    ff = tk.LabelFrame(left, text=" Formel des aktuellen Schritts ", bg=BG, fg=FG)
    ff.pack(padx=12, pady=(8, 0), fill="x")
    formula_box = tk.Text(ff, height=8, font=small, bg="#ffffff", fg=FG, relief="flat",
                          wrap="none", state="disabled")
    formula_box.pack(fill="x", padx=6, pady=4)

    # --- Key-Schedule-Tabelle
    ks = tk.LabelFrame(body, text=" Key-Schedule (w0..w43) ", bg=BG, fg=FG)
    ks.pack(side="right", padx=(0, 12), pady=8, anchor="n")
    ks_labels = []
    tk.Label(ks, text="Runde", bg=BG, fg=FG, font=small).grid(row=0, column=0, padx=4)
    for c in range(4):
        tk.Label(ks, text=f"Wort {c}", bg=BG, fg=FG, font=small).grid(row=0, column=c + 1, padx=8)
    for rnd in range(11):
        tk.Label(ks, text=str(rnd), bg=BG, fg=FG, font=small).grid(row=rnd + 1, column=0)
        row = []
        for c in range(4):
            lb = tk.Label(ks, text="", font=small, bg=CELL, fg=FG, width=9)
            lb.grid(row=rnd + 1, column=c + 1, padx=2, pady=1)
            row.append(lb)
        ks_labels.append(row)

    out_var = tk.StringVar()
    tk.Label(left, textvariable=out_var, bg=BG, fg="#1a7f37", font=f_out).pack()

    # --- Steuerung
    S = {"steps": [], "w": [], "i": 0, "play": False, "job": None}
    prog_var = tk.StringVar()

    def hexb(v):
        return f"{v:02x}"

    def show():
        st = S["steps"][S["i"]]
        title_var.set(st["title"])
        info_var.set(st["info"])
        prog_var.set(f"Schritt {S['i'] + 1} / {len(S['steps'])}")
        formula_box.config(state="normal")
        formula_box.delete("1.0", "end")
        formula_box.insert("1.0", formula_text(st, S["w"]))
        formula_box.config(state="disabled")
        for r in range(4):
            for c in range(4):
                p = st["prev"]
                prev_cells[r][c].config(text=hexb(p[r][c]) if p else "--", bg=CELL, fg=FG)
                changed = p is not None and p[r][c] != st["state"][r][c]
                cur_cells[r][c].config(text=hexb(st["state"][r][c]),
                                       bg=CHG if changed else CELL, fg="#11111b" if changed else FG)
                k = st["key"]
                key_cells[r][c].config(text=hexb(k[r][c]) if k else "--",
                                       bg=KEYC if k else CELL, fg="#11111b" if k else FG)
        for rnd in range(11):
            active = rnd == st["round"]
            for c in range(4):
                ks_labels[rnd][c].config(bg=KEYC if active and st["key"] else (CHG if active else CELL),
                                         fg="#11111b" if active else FG)
        if S["i"] == len(S["steps"]) - 1:
            out_var.set("Chiffretext: " + state_to_bytes(st["state"]).hex())
        else:
            out_var.set("")

    def load():
        try:
            if mode_var.get() == "text":
                raw = pt_var.get().encode("utf-8")
                if len(raw) > 15:
                    raise ValueError("Der Klartext darf im Text-Modus hoechstens 15 Bytes lang sein (ein AES-Block).")
                pt = pad(raw)
                key = key_var.get().encode("utf-8")
                if len(key) != 16:
                    raise ValueError(f"Der Schluessel muss genau 16 Bytes lang sein (aktuell {len(key)}).")
                bytes_var.set(f"Klartext-Bytes: {pt.hex()}  (\"{pt_var.get()}\" + PKCS#7-Padding auf 16 Bytes)\n"
                              f"Schluessel-Bytes: {key.hex()}")
            else:
                pt = bytes.fromhex(pt_var.get().strip())
                key = bytes.fromhex(key_var.get().strip())
                if len(pt) != 16 or len(key) != 16:
                    raise ValueError("Klartext und Schluessel muessen je genau 32 Hex-Zeichen (16 Bytes) sein.")
                bytes_var.set("")
        except ValueError as e:
            messagebox.showerror("Fehler", str(e) if str(e) and "hex" not in str(e).lower()
                                 else "Klartext und Schluessel muessen je genau 32 Hex-Zeichen (16 Bytes) sein.")
            return
        S["steps"], S["w"] = build_steps(pt, key)
        S["i"] = 0
        for rnd in range(11):
            for c in range(4):
                ks_labels[rnd][c].config(text=bytes(S["w"][4 * rnd + c]).hex())
        show()

    def goto(i):
        if S["steps"]:
            S["i"] = max(0, min(len(S["steps"]) - 1, i))
            show()

    def stop():
        S["play"] = False
        if S["job"]:
            root.after_cancel(S["job"])
            S["job"] = None
        play_btn.config(text="▶ Auto")

    def tick():
        if not S["play"]:
            return
        if S["i"] >= len(S["steps"]) - 1:
            stop()
            return
        goto(S["i"] + 1)
        S["job"] = root.after(120, tick)

    def toggle_play():
        if S["play"]:
            stop()
        else:
            if S["i"] >= len(S["steps"]) - 1:
                goto(0)
            S["play"] = True
            play_btn.config(text="⏸ Stopp")
            S["job"] = root.after(120, tick)

    ttk.Button(bar, text="Berechnen / Reset", command=lambda: (stop(), load())).pack(side="left", padx=4)
    ttk.Button(bar, text="⏮", width=3, command=lambda: (stop(), goto(0))).pack(side="left", padx=2)
    ttk.Button(bar, text="◀ Zurueck", command=lambda: (stop(), goto(S["i"] - 1))).pack(side="left", padx=2)
    ttk.Button(bar, text="Weiter ▶", command=lambda: (stop(), goto(S["i"] + 1))).pack(side="left", padx=2)
    ttk.Button(bar, text="⏭", width=3, command=lambda: (stop(), goto(len(S["steps"]) - 1))).pack(side="left", padx=2)
    play_btn = ttk.Button(bar, text="▶ Auto", command=toggle_play)
    play_btn.pack(side="left", padx=8)
    tk.Label(bar, textvariable=prog_var, bg=BG, fg=FG).pack(side="left", padx=8)

    root.bind("<Right>", lambda e: (stop(), goto(S["i"] + 1)))
    root.bind("<Left>", lambda e: (stop(), goto(S["i"] - 1)))
    root.bind("<space>", lambda e: toggle_play())

    # --- Automatische Skalierung: alles passt immer ins Fenster (ohne Scrollen)
    scale = {"v": 1.0, "busy": False}

    def apply_scale(v):
        scale["v"] = v
        for f, base in FONTS.values():
            f.configure(size=-max(5, round(base * 4 / 3 * v)))

    def fit(_event=None):
        if scale["busy"]:
            return
        scale["busy"] = True
        try:
            for _ in range(8):
                root.update_idletasks()
                W, H = root.winfo_width(), root.winfo_height()
                info_lbl.config(wraplength=max(200, int((W - 40) * 0.62)))
                root.update_idletasks()
                rw = max(page.winfo_reqwidth(), bar.winfo_reqwidth()) + 4
                rh = page.winfo_reqheight() + bar.winfo_reqheight() + 16
                f = min(W / rw, H / rh)
                if 0.985 <= f <= 1.005:
                    break
                apply_scale(min(2.5, max(0.3, scale["v"] * f * 0.995)))
        finally:
            scale["busy"] = False

    root.bind("<Configure>", lambda e: fit() if e.widget is root else None)
    root.update_idletasks()
    fit()

    load()
    root.mainloop()


if __name__ == "__main__":
    if "--test" in sys.argv:
        self_test()
    else:
        run_gui()
