import threading
import requests
from requests.exceptions import SSLError
import time
import json
import os
import hashlib
from pathlib import Path
from urllib.parse import urlparse
import re
import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import scrolledtext
from tkinter import ttk


class LogReaderThread(threading.Thread):
    def __init__(self, url, update_callback, interval=1.0, proxies=None, verify=True, prompt_callback=None, auto_accept_ssl=False):
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
        self.proxies = proxies or {}
        self.verify = verify
        # callback(url) -> bool (whether to continue ignoring SSL)
        self.prompt_callback = prompt_callback
        self.auto_accept_ssl = bool(auto_accept_ssl)

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

                try:
                    resp = requests.get(self.url, headers=headers, stream=False, timeout=10, proxies=self.proxies or None, verify=self.verify)
                    # If server responds with 416 Range Not Satisfiable, file was likely rotated/truncated
                    if resp.status_code == 416:
                        # Reset tracking and fetch full file
                        self._pos = 0
                        self._last_content = b""
                        try:
                            full = requests.get(self.url, timeout=10, proxies=self.proxies or None, verify=self.verify)
                            if full.status_code == 200:
                                content = full.content
                                # replace whole view because file restarted
                                self._pos = len(content)
                                self._last_content = content
                                self.update_callback(content.decode('utf-8', errors='replace'), replace=True)
                                time.sleep(self.interval)
                                continue
                        except Exception:
                            time.sleep(self.interval)
                            continue
                except SSLError as e:
                    # If SSL error, ask user (via prompt_callback) whether to continue ignoring SSL errors
                    # Do not write SSL errors into the log buffer (avoid polluting the log view)
                    if self.auto_accept_ssl:
                        self.verify = False
                        # retry immediately
                        time.sleep(0.1)
                        continue
                    if self.prompt_callback:
                        try:
                            should_ignore = self.prompt_callback(self.url)
                        except Exception:
                            should_ignore = False
                        if should_ignore:
                            self.verify = False
                            # next loop will retry immediately
                            time.sleep(0.1)
                            continue
                    time.sleep(self.interval)
                    continue

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
    def __init__(self, notebook, url, name=None, interval=1.0, proxies=None, verify=True, prompt_callback=None, auto_scroll_default=False, cache_path=None, use_cache=False, trust_store=None):
        self.frame = ttk.Frame(notebook)
        self.url = url
        self.name = name or url
        self.text = scrolledtext.ScrolledText(self.frame, wrap='none', height=30)
        self.text.pack(fill='both', expand=True)
        # add horizontal scrollbar
        try:
            hscroll = ttk.Scrollbar(self.frame, orient='horizontal', command=self.text.xview)
            self.text.configure(xscrollcommand=hscroll.set)
            hscroll.pack(fill='x')
        except Exception:
                pass
        self.text.configure(state='disabled')
        # keep full buffer in memory to allow filtering/searching
        self.buffer = ""
        self.matches = []
        self.current_match = -1
        # Auto-scroll default off: do not force user to the end on updates
        self.auto_scroll = tk.BooleanVar(value=auto_scroll_default)

        # cache settings
        self.use_cache = bool(use_cache)
        self.cache_path = cache_path
        if self.use_cache and self.cache_path:
            try:
                p = Path(self.cache_path)
                if p.exists():
                    with p.open('r', encoding='utf-8', errors='replace') as f:
                        self.buffer = f.read()
            except Exception:
                self.buffer = ""

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

        # pass proxies/verify and a prompt callback so threads can ask GUI to ignore SSL
        self._prompt_cb = prompt_callback
        self.trust_store = trust_store
        self.thread = LogReaderThread(self.url, self._on_update, interval=interval, proxies=proxies, verify=verify, prompt_callback=self.prompt_ssl_continue)
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
            # overwrite cache file if using cache
            if self.use_cache and self.cache_path:
                try:
                    with open(self.cache_path, 'w', encoding='utf-8', errors='replace') as f:
                        f.write(self.buffer)
                except Exception:
                    pass
        else:
            self.buffer += new_text
            # append to cache file
            if self.use_cache and self.cache_path and new_text:
                try:
                    with open(self.cache_path, 'a', encoding='utf-8', errors='replace') as f:
                        f.write(new_text)
                except Exception:
                    pass

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

        # preserve current view fraction so user doesn't get moved to start on updates
        try:
            first_frac = first
        except NameError:
            try:
                first_frac = self.text.yview()[0]
            except Exception:
                first_frac = 0.0

        self.text.configure(state='normal')
        self.text.delete('1.0', tk.END)
        self.text.insert(tk.END, view)
        self.clear_highlight()
        # re-run highlight for current search
        if self.search_var.get().strip():
            self.highlight_matches(self.search_var.get().strip())

        try:
            if self.auto_scroll.get() and at_bottom_before:
                self.text.see(tk.END)
            else:
                # restore previous view position proportionally
                self.text.yview_moveto(first_frac)
        except Exception:
            pass

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

    def prompt_ssl_continue(self, url):
        # Called from background thread. Schedule a dialog in main thread and wait for result.
        ev = threading.Event()
        result = {}

        def ask():
            ans = messagebox.askyesno('SSL inseguro', f'El certificado de {url} parece inseguro. ¿Continuar e ignorar errores SSL para esta conexión?')
            result['ans'] = ans
            ev.set()

        try:
            # schedule on GUI thread
            self.text.after(0, ask)
            ev.wait()
            ans = bool(result.get('ans'))
            if ans and self.trust_store:
                # persist trust for this host so future connections won't prompt
                try:
                    host = urlparse(url).hostname
                    if host:
                        try:
                            self.trust_store(host)
                        except Exception:
                            pass
                except Exception:
                    pass
            return ans
        except Exception:
            return False

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

        # config path
        self.config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        cfg = self.load_config()

        # global network/settings
        self.proxies = cfg.get('proxies', {})
        self.verify_default = cfg.get('verify_default', True)
        self.auto_scroll_default = cfg.get('auto_scroll_default', False)
        self.use_cache_default = cfg.get('use_cache_default', False)
        self.auto_accept_ssl = cfg.get('auto_accept_ssl', False)

        # session path
        self.session_path = os.path.join(os.path.dirname(__file__), 'session.json')

        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label='Añadir log...', command=self.add_log_dialog)
        filemenu.add_command(label='Cerrar pestaña', command=self.close_current_tab)
        # keep a persistent BooleanVar for the menu checkbutton so it reflects changes
        self._auto_accept_ssl_var = tk.BooleanVar(value=self.auto_accept_ssl)
        filemenu.add_checkbutton(label='Auto-aceptar SSL', variable=self._auto_accept_ssl_var, command=self.toggle_auto_accept_ssl)
        filemenu.add_separator()
        filemenu.add_command(label='Configuración...', command=self.open_settings)
        filemenu.add_separator()
        filemenu.add_command(label='Salir', command=self.on_exit)
        menubar.add_cascade(label='Archivo', menu=filemenu)
        root.config(menu=menubar)

        self.trusted_hosts = cfg.get('trusted_hosts', [])
        self.tabs = {}
        # restore previous session (after tabs dict created)
        try:
            self.load_session()
        except Exception:
            pass

    def add_log(self, url, name=None, interval=1.0):
        # create cache dir
        cache_dir = os.path.join(os.path.dirname(__file__), 'cache')
        os.makedirs(cache_dir, exist_ok=True)
        # deterministic cache filename from url
        h = hashlib.sha1(url.encode('utf-8')).hexdigest()
        safe_name = f"log_{h}.log"
        cache_path = os.path.join(cache_dir, safe_name)
        # determine if this host is already trusted
        try:
            host = urlparse(url).hostname
        except Exception:
            host = None
        verify_flag = self.verify_default
        if host and host in self.trusted_hosts:
            verify_flag = False

        tab = LogTab(self.notebook, url, name=name, interval=interval, proxies=self.proxies, verify=verify_flag, prompt_callback=None, auto_scroll_default=self.auto_scroll_default, cache_path=cache_path, use_cache=self.use_cache_default, trust_store=self.add_trusted_host)
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

    def toggle_auto_accept_ssl(self):
        # toggle the flag and apply to running threads
        try:
            val = bool(self._auto_accept_ssl_var.get())
            self.auto_accept_ssl = val
            for tab in list(self.tabs.values()):
                try:
                    tab.thread.auto_accept_ssl = val
                except Exception:
                    pass
            # persist change to config immediately
            try:
                cfg = self.load_config()
                cfg['auto_accept_ssl'] = self.auto_accept_ssl
                self.save_config(cfg)
            except Exception:
                pass
        except Exception:
            pass

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
        # save session
        try:
            self.save_session()
        except Exception:
            pass
        self.root.quit()

    def save_session(self):
        session = {'tabs': []}
        for tab in list(self.tabs.values()):
            try:
                item = {
                    'url': tab.url,
                    'name': tab.name,
                    'interval': tab.thread.interval,
                    'use_cache': bool(tab.use_cache),
                }
                session['tabs'].append(item)
            except Exception:
                pass
        try:
            with open(self.session_path, 'w', encoding='utf-8') as f:
                json.dump(session, f, indent=2)
        except Exception:
            pass

    def load_session(self):
        try:
            if os.path.exists(self.session_path):
                with open(self.session_path, 'r', encoding='utf-8') as f:
                    session = json.load(f)
                for t in session.get('tabs', []):
                    try:
                        self.add_log(t.get('url'), name=t.get('name'), interval=t.get('interval', 1.0))
                    except Exception:
                        pass
        except Exception:
            pass

    def load_config(self):
        # Load config.json or create default
        default = {'proxies': {}, 'verify_default': True, 'auto_scroll_default': False, 'use_cache_default': False, 'auto_accept_ssl': False}
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # merge defaults
                    for k, v in default.items():
                        data.setdefault(k, v)
                    return data
            else:
                # create default file
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(default, f, indent=2)
                return default
        except Exception:
            return default

    def save_config(self, cfg):
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    def add_trusted_host(self, host):
        try:
            if not hasattr(self, 'trusted_hosts'):
                self.trusted_hosts = []
            if host and host not in self.trusted_hosts:
                self.trusted_hosts.append(host)
                cfg = self.load_config()
                cfg['trusted_hosts'] = self.trusted_hosts
                try:
                    self.save_config(cfg)
                except Exception:
                    pass
        except Exception:
            pass

    def open_settings(self):
        # Simple settings dialog to set proxies and default SSL verify
        dlg = tk.Toplevel(self.root)
        dlg.title('Configuración de red')
        dlg.transient(self.root)

        ttk.Label(dlg, text='HTTP proxy (ej. http://user:pass@proxy:3128):').grid(row=0, column=0, sticky='w')
        http_var = tk.StringVar(value=self.proxies.get('http', ''))
        http_e = ttk.Entry(dlg, textvariable=http_var, width=60)
        http_e.grid(row=0, column=1, padx=6, pady=4)

        ttk.Label(dlg, text='HTTPS proxy (ej. http://user:pass@proxy:3128):').grid(row=1, column=0, sticky='w')
        https_var = tk.StringVar(value=self.proxies.get('https', ''))
        https_e = ttk.Entry(dlg, textvariable=https_var, width=60)
        https_e.grid(row=1, column=1, padx=6, pady=4)

        verify_var = tk.BooleanVar(value=self.verify_default)
        ttk.Checkbutton(dlg, text='Verificar certificados SSL (recomendado)', variable=verify_var).grid(row=2, column=0, columnspan=1, sticky='w', padx=6)

        autos_var = tk.BooleanVar(value=self.auto_scroll_default)
        ttk.Checkbutton(dlg, text='Auto-scroll al final por defecto', variable=autos_var).grid(row=2, column=1, columnspan=1, sticky='w', padx=6)

        cache_var = tk.BooleanVar(value=self.use_cache_default)
        ttk.Checkbutton(dlg, text='Usar caché local para logs (guardar en disco)', variable=cache_var).grid(row=3, column=0, columnspan=2, sticky='w', padx=6, pady=4)

        autoaccept_var = tk.BooleanVar(value=self.auto_accept_ssl)
        ttk.Checkbutton(dlg, text='Auto-aceptar errores SSL (ignorar certificados inválidos)', variable=autoaccept_var).grid(row=4, column=0, columnspan=2, sticky='w', padx=6, pady=4)

        def save():
            p = {}
            if http_var.get().strip():
                p['http'] = http_var.get().strip()
            if https_var.get().strip():
                p['https'] = https_var.get().strip()
            self.proxies = p
            self.verify_default = bool(verify_var.get())
            self.auto_scroll_default = bool(autos_var.get())
            self.use_cache_default = bool(cache_var.get())
            self.auto_accept_ssl = bool(autoaccept_var.get())
            # update existing tabs
            for tab in list(self.tabs.values()):
                try:
                    tab.thread.proxies = dict(self.proxies)
                    tab.thread.verify = self.verify_default
                    tab.auto_scroll.set(self.auto_scroll_default)
                    tab.use_cache = self.use_cache_default
                    tab.thread.auto_accept_ssl = self.auto_accept_ssl
                except Exception:
                    pass
            # save to config
            cfg = {
                'proxies': self.proxies,
                'verify_default': self.verify_default,
                'auto_scroll_default': self.auto_scroll_default,
                'use_cache_default': self.use_cache_default,
                'auto_accept_ssl': self.auto_accept_ssl,
            }
            try:
                self.save_config(cfg)
            except Exception:
                pass
            dlg.destroy()

        ttk.Button(dlg, text='Guardar', command=save).grid(row=5, column=0, pady=8)
        ttk.Button(dlg, text='Cancelar', command=dlg.destroy).grid(row=5, column=1, pady=8)


def main():
    root = tk.Tk()
    app = LogViewerApp(root)

    # Example tab (user can remove)
    # app.add_log('http://web.com/LOGS/estoEsUnLog.log', name='Ejemplo', interval=1.0)

    root.protocol('WM_DELETE_WINDOW', app.on_exit)
    root.mainloop()


if __name__ == '__main__':
    main()
