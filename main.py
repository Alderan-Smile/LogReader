import threading
import requests
import time
import re
import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import scrolledtext
from tkinter import ttk


class LogReaderThread(threading.Thread):
    def __init__(self, url, update_callback, interval=1.0):
        super().__init__(daemon=True)
        self.url = url
        self.update_callback = update_callback
        self.interval = interval
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._pos = 0
        self._etag = None
        self._last_content = b""

    def run(self):
        while not self._stop_event.is_set():
            self._pause_event.wait()
            try:
                headers = {}
                # Try to use Range if we have a position
                if self._pos > 0:
                    headers['Range'] = f'bytes={self._pos}-'
                if self._etag:
                    headers['If-None-Match'] = self._etag

                resp = requests.get(self.url, headers=headers, stream=False, timeout=10)

                if resp.status_code in (200, 206):
                    content = resp.content
                    # If server responded with partial content (206) append from 0
                    if resp.status_code == 206:
                        if content:
                            self._pos += len(content)
                            self.update_callback(content.decode('utf-8', errors='replace'))
                    else:
                        # 200 OK: server may not support Range. Compare length.
                        if len(content) < len(self._last_content):
                            # Log rotated/truncated: replace all
                            self._pos = len(content)
                            self._last_content = content
                            self.update_callback(content.decode('utf-8', errors='replace'), replace=True)
                        elif len(content) > len(self._last_content):
                            new_part = content[len(self._last_content):]
                            self._pos = len(content)
                            self._last_content = content
                            self.update_callback(new_part.decode('utf-8', errors='replace'))
                        # else: unchanged

                    # Save ETag if provided
                    etag = resp.headers.get('ETag')
                    if etag:
                        self._etag = etag

                elif resp.status_code == 304:
                    # Not modified
                    pass
                else:
                    self.update_callback(f"\n[Error] HTTP {resp.status_code} reading {self.url}\n")

            except Exception as e:
                self.update_callback(f"\n[Error] {e}\n")

            time.sleep(self.interval)

    def stop(self):
        self._stop_event.set()
        self._pause_event.set()

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

    def set_interval(self, interval):
        self.interval = interval


class LogTab:
    def __init__(self, notebook, url, name=None, interval=1.0):
        self.frame = ttk.Frame(notebook)
        self.url = url
        self.name = name or url
        self.text = scrolledtext.ScrolledText(self.frame, wrap='none', height=30)
        self.text.pack(fill='both', expand=True)
        self.text.configure(state='disabled')
        # keep full buffer in memory to allow filtering/searching
        self.buffer = ""
        self.matches = []
        self.current_match = -1
        # Auto-scroll default off: do not force user to the end on updates
        self.auto_scroll = tk.BooleanVar(value=False)

        controls = ttk.Frame(self.frame)
        controls.pack(fill='x')

        ttk.Label(controls, text='Interval (s):').pack(side='left')
        self.interval_var = tk.DoubleVar(value=interval)
        self.interval_spin = ttk.Spinbox(controls, from_=0.1, to=60.0, increment=0.1, textvariable=self.interval_var, width=6)
        self.interval_spin.pack(side='left')

        self.pause_btn = ttk.Button(controls, text='Pausar', command=self.toggle_pause)
        self.pause_btn.pack(side='left', padx=4)

        self.clear_btn = ttk.Button(controls, text='Limpiar', command=self.clear)
        self.clear_btn.pack(side='left', padx=4)

        ttk.Checkbutton(controls, text='Auto-scroll', variable=self.auto_scroll).pack(side='left', padx=8)

        self.thread = LogReaderThread(self.url, self._on_update, interval=interval)
        self.thread.start()

        # --- Controls: búsqueda / filtro / resaltado ---
        ctrl2 = ttk.Frame(self.frame)
        ctrl2.pack(fill='x', pady=2)

        ttk.Label(ctrl2, text='Buscar:').pack(side='left')
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(ctrl2, textvariable=self.search_var, width=30)
        self.search_entry.pack(side='left', padx=4)
        ttk.Button(ctrl2, text='Buscar', command=self.perform_search).pack(side='left')
        ttk.Button(ctrl2, text='Prev', command=self.goto_prev_match).pack(side='left', padx=2)
        ttk.Button(ctrl2, text='Next', command=self.goto_next_match).pack(side='left', padx=2)

        ttk.Label(ctrl2, text='Filtro (regex/opcional):').pack(side='left', padx=8)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(ctrl2, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side='left', padx=4)
        ttk.Button(ctrl2, text='Aplicar filtro', command=self.apply_filter).pack(side='left')
        ttk.Button(ctrl2, text='Limpiar filtro', command=self.clear_filter).pack(side='left', padx=2)

        # Tag for highlights
        self.text.tag_config('hl', background='yellow')

    def _on_update(self, new_text, replace=False):
        # maintain internal buffer then refresh view according to any filter
        if replace:
            self.buffer = new_text
        else:
            self.buffer += new_text

        def ui_update():
            self.refresh_view()

        try:
            self.text.after(0, ui_update)
        except tk.TclError:
            pass

    def refresh_view(self):
        # determine whether view is currently at bottom (before update)
        try:
            first, last = self.text.yview()
            at_bottom_before = last >= 0.995
        except Exception:
            at_bottom_before = True

        # apply filter if present
        filt = self.filter_var.get().strip()
        if filt:
            try:
                pattern = re.compile(filt)
                lines = [l for l in self.buffer.splitlines(True) if pattern.search(l)]
                view = ''.join(lines)
            except re.error:
                # invalid regex: fallback to substring
                view = ''.join([l for l in self.buffer.splitlines(True) if filt in l])
        else:
            view = self.buffer

        self.text.configure(state='normal')
        self.text.delete('1.0', tk.END)
        self.text.insert(tk.END, view)
        self.clear_highlight()
        # re-run highlight for current search
        if self.search_var.get().strip():
            self.highlight_matches(self.search_var.get().strip())
        # Only auto-scroll if the user enabled it AND the view was already at the bottom
        if self.auto_scroll.get() and at_bottom_before:
            self.text.see(tk.END)
        self.text.configure(state='disabled')

    def toggle_pause(self):
        if self.thread._pause_event.is_set():
            self.thread.pause()
            self.pause_btn.config(text='Reanudar')
        else:
            # apply any interval change
            try:
                val = float(self.interval_var.get())
            except Exception:
                val = self.thread.interval
            self.thread.set_interval(val)
            self.thread.resume()
            self.pause_btn.config(text='Pausar')

    def clear(self):
        self.buffer = ""
        self.text.configure(state='normal')
        self.text.delete('1.0', tk.END)
        self.text.configure(state='disabled')

    def apply_filter(self):
        try:
            self.refresh_view()
        except Exception as e:
            messagebox.showerror('Filtro', f'Error aplicando filtro: {e}')

    def clear_filter(self):
        self.filter_var.set('')
        self.refresh_view()

    def highlight_matches(self, term):
        self.clear_highlight()
        if not term:
            return
        try:
            pattern = re.compile(term)
        except re.error:
            pattern = None

        text = self.text.get('1.0', tk.END)
        self.matches = []
        if pattern:
            for m in pattern.finditer(text):
                start = f"1.0+{m.start()}c"
                end = f"1.0+{m.end()}c"
                self.text.tag_add('hl', start, end)
                self.matches.append((start, end))
        else:
            # plain substring
            term_esc = term
            idx = '1.0'
            while True:
                idx = self.text.search(term_esc, idx, nocase=1, stopindex=tk.END)
                if not idx:
                    break
                end = f"{idx}+{len(term)}c"
                self.text.tag_add('hl', idx, end)
                self.matches.append((idx, end))
                idx = end

    def clear_highlight(self):
        try:
            self.text.tag_remove('hl', '1.0', tk.END)
        except Exception:
            pass

    def perform_search(self):
        term = self.search_var.get().strip()
        if not term:
            return
        self.text.configure(state='normal')
        self.highlight_matches(term)
        self.text.configure(state='disabled')
        # set current match index
        self.current_match = 0 if self.matches else -1
        if self.current_match != -1:
            self.goto_match(self.current_match)

    def goto_match(self, index):
        if not self.matches:
            return
        start, end = self.matches[index]
        self.text.configure(state='normal')
        self.text.tag_remove('sel', '1.0', tk.END)
        self.text.tag_add('sel', start, end)
        self.text.see(start)
        self.text.configure(state='disabled')

    def goto_next_match(self):
        if not self.matches:
            return
        self.current_match = (self.current_match + 1) % len(self.matches)
        self.goto_match(self.current_match)

    def goto_prev_match(self):
        if not self.matches:
            return
        self.current_match = (self.current_match - 1) % len(self.matches)
        self.goto_match(self.current_match)

    def stop(self):
        self.thread.stop()


class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Log Viewer')
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label='Añadir log...', command=self.add_log_dialog)
        filemenu.add_command(label='Cerrar pestaña', command=self.close_current_tab)
        filemenu.add_separator()
        filemenu.add_command(label='Salir', command=self.on_exit)
        menubar.add_cascade(label='Archivo', menu=filemenu)
        root.config(menu=menubar)

        self.tabs = {}

    def add_log(self, url, name=None, interval=1.0):
        tab = LogTab(self.notebook, url, name=name, interval=interval)
        display = name or url
        self.notebook.add(tab.frame, text=display)
        self.tabs[tab.frame] = tab

    def add_log_dialog(self):
        url = simpledialog.askstring('Añadir log', 'URL del log:')
        if not url:
            return
        name = simpledialog.askstring('Nombre (opcional)', 'Nombre de la pestaña:')
        try:
            interval = float(simpledialog.askstring('Intervalo', 'Intervalo de refresco en segundos:', initialvalue='1'))
        except Exception:
            interval = 1.0
        self.add_log(url, name=name, interval=interval)

    def close_current_tab(self):
        cur = self.notebook.select()
        if not cur:
            return
        frame = self.root.nametowidget(cur)
        tab = self.tabs.pop(frame, None)
        if tab:
            tab.stop()
        self.notebook.forget(frame)

    def on_exit(self):
        # stop all threads
        for tab in list(self.tabs.values()):
            tab.stop()
        self.root.quit()


def main():
    root = tk.Tk()
    app = LogViewerApp(root)

    # Example tab (user can remove)
    # app.add_log('http://web.com/LOGS/estoEsUnLog.log', name='Ejemplo', interval=1.0)

    root.protocol('WM_DELETE_WINDOW', app.on_exit)
    root.mainloop()


if __name__ == '__main__':
    main()
