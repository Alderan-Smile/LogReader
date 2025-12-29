import os
import json
import hashlib
from urllib.parse import urlparse
import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import ttk

from tab import LogTab


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
