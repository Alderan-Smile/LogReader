import threading
import queue
import mmap
import os
import re
from urllib.parse import urlparse
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import Listbox

from reader import LogReaderThread


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
        # keep small buffer in memory to allow filtering/searching of visible area
        # for very large logs we avoid loading full cache into memory
        self.view_bytes = 65536
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
                    # load only the last view_bytes to avoid memory spikes
                    with p.open('rb') as f:
                        try:
                            f.seek(0, os.SEEK_END)
                            sz = f.tell()
                            start = max(0, sz - self.view_bytes)
                            f.seek(start)
                            data = f.read()
                            # decode safely
                            self.buffer = data.decode('utf-8', errors='replace')
                        except Exception:
                            self.buffer = ""
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
        # pass tail_bytes so initial load fetches only the end
        self.thread = LogReaderThread(self.url, self._on_update, interval=interval, proxies=proxies, verify=verify, prompt_callback=self.prompt_ssl_continue, tail_bytes=self.view_bytes)
        self.thread.start()

        # --- Controls: búsqueda / filtro / resaltado ---
        ctrl2 = ttk.Frame(self.frame)
        ctrl2.pack(fill='x', pady=2)

        ttk.Label(ctrl2, text='Buscar:').pack(side='left')
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(ctrl2, textvariable=self.search_var, width=30)
        self.search_entry.pack(side='left', padx=4)
        ttk.Button(ctrl2, text='Buscar', command=self.perform_search).pack(side='left')
        # bind debounce for realtime search
        self._search_after_id = None
        self.search_entry.bind('<KeyRelease>', lambda e: self._on_search_change())
        ttk.Button(ctrl2, text='Buscar archivo', command=self.perform_search_full).pack(side='left', padx=2)
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
        # UI feedback for background search
        self.search_status = tk.StringVar(value='')
        ttk.Label(self.frame, textvariable=self.search_status, foreground='blue').pack(fill='x')
        self._search_thread = None
        self._search_queue = queue.Queue()
        self._showing_search_results = False
        # UI widget for search results (hidden until needed)
        self._results_frame = ttk.Frame(self.frame)
        self._results_list = Listbox(self._results_frame, height=8)
        self._results_list.pack(fill='both', expand=True)
        self._results_frame.pack_forget()
        self._results_list.bind('<<ListboxSelect>>', lambda e: self._on_result_select())

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

    def _on_search_change(self):
        # debounce key presses
        try:
            if self._search_after_id:
                self.text.after_cancel(self._search_after_id)
        except Exception:
            pass
        self._search_after_id = self.text.after(300, self.perform_search)

    def perform_search(self):
        term = self.search_var.get().strip()
        if not term:
            return
        # If a previous search thread is running, ignore or wait
        if self._search_thread and self._search_thread.is_alive():
            # indicate queued
            self.search_status.set('Buscando (en cola)...')
            return

        # Start background search over cache file if available, otherwise over buffer
        if self.use_cache and self.cache_path and os.path.exists(self.cache_path):
            self.search_status.set('Buscando en archivo...')
            self._search_thread = threading.Thread(target=self._search_in_file, args=(term,), daemon=True)
            self._search_thread.start()
            self._poll_search()
        else:
            # small search in memory buffer
            try:
                self.text.configure(state='normal')
                self.clear_highlight()
                self.highlight_matches(term)
                self.text.configure(state='disabled')
                self.current_match = 0 if self.matches else -1
                if self.current_match != -1:
                    self.goto_match(self.current_match)
            except Exception:
                pass

    def _poll_search(self):
        # poll queue for results
        try:
            res = self._search_queue.get_nowait()
        except queue.Empty:
            if self._search_thread and self._search_thread.is_alive():
                self.text.after(100, self._poll_search)
            else:
                self.search_status.set('')
            return

        # res is list of tuples (byte_offset, line)
        matches = res
        self._showing_search_results = True
        try:
            # populate results listbox with preview lines
            self._results_list.delete(0, tk.END)
            for off, line in matches:
                preview = line.strip()
                if len(preview) > 200:
                    preview = preview[:197] + '...'
                self._results_list.insert(tk.END, preview)
            # show results frame
            self._results_frame.pack(fill='both', padx=4, pady=4)
            self.search_status.set(f'Mostrando {len(matches)} coincidencias')
            # try to highlight matches inside current buffer quickly
            try:
                term = self.search_var.get().strip()
                if term:
                    self.text.configure(state='normal')
                    self.clear_highlight()
                    self.highlight_matches(term)
                    self.text.configure(state='disabled')
            except Exception:
                pass
        except Exception:
            pass

    def _search_in_file(self, term):
        # background file search using mmap for performance
        matches = []
        try:
            is_regex = False
            try:
                pattern = re.compile(term)
                is_regex = True
            except re.error:
                is_regex = False
            MAX_MATCHES = 1000
            with open(self.cache_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    if is_regex:
                        # compile a bytes-pattern so we can run over mmap (bytes)
                        try:
                            pattern_b = re.compile(term.encode('utf-8'))
                        except re.error:
                            # fallback to plain string regex on decoded chunks (slower)
                            pattern_b = None

                        if pattern_b is not None:
                            for mobj in pattern_b.finditer(m):
                                start = mobj.start()
                                # extract line
                                line_start = m.rfind(b'\n', 0, start) + 1
                                line_end = m.find(b'\n', start)
                                if line_end == -1:
                                    line_end = m.size()
                                line = m[line_start:line_end].decode('utf-8', errors='replace')
                                matches.append((line_start, line + '\n'))
                                if len(matches) >= MAX_MATCHES:
                                    break
                        else:
                            # fallback: decode in chunks to avoid decoding whole file
                            # This is slower but avoids type issues
                            data = m[:].decode('utf-8', errors='replace')
                            for mobj in re.finditer(term, data):
                                line_start_char = data.rfind('\n', 0, mobj.start()) + 1
                                line_end_char = data.find('\n', mobj.start())
                                if line_end_char == -1:
                                    line_end_char = len(data)
                                line = data[line_start_char:line_end_char]
                                # approximate byte offset by encoding portion before line
                                byte_offset = data[:line_start_char].encode('utf-8', errors='replace')
                                matches.append((len(byte_offset), line + '\n'))
                                if len(matches) >= MAX_MATCHES:
                                    break
                    else:
                        needle = term.encode('utf-8')
                        idx = 0
                        while True:
                            idx = m.find(needle, idx)
                            if idx == -1:
                                break
                            line_start = m.rfind(b'\n', 0, idx) + 1
                            line_end = m.find(b'\n', idx)
                            if line_end == -1:
                                line_end = m.size()
                            line = m[line_start:line_end].decode('utf-8', errors='replace')
                            matches.append((line_start, line + '\n'))
                            if len(matches) >= MAX_MATCHES:
                                break
                            idx = idx + len(needle)
        except Exception:
            matches = ['[Error buscando en archivo]\n']

        # put results in queue for UI thread
        try:
            # limit to first 1000 matches to avoid huge UI
            self._search_queue.put(matches[:1000])
        except Exception:
            pass

    def _on_result_select(self):
        # Called when user selects a result from the results listbox
        sel = self._results_list.curselection()
        if not sel:
            return
        idx = sel[0]
        try:
            item = self._search_queue.get_nowait()
            # put it back for future polls
            self._search_queue.put(item)
        except Exception:
            pass
        # We don't keep matches stored long-term; instead, recompute by running search thread synchronously for this index
        try:
            # read the corresponding line/offset from cache by re-running a small read
            with open(self.cache_path, 'rb') as f:
                # We will iterate the file until we reach the idx-th match (inefficient for large idx but acceptable)
                count = 0
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    term = self.search_var.get().strip().encode('utf-8')
                    p = 0
                    while True:
                        p = m.find(term, p)
                        if p == -1:
                            break
                        line_start = m.rfind(b'\n', 0, p) + 1
                        if count == idx:
                            # load a chunk around line_start
                            start = max(0, line_start - 4096)
                            end = min(m.size(), line_start + 16384)
                            chunk = m[start:end]
                            try:
                                s = chunk.decode('utf-8', errors='replace')
                            except Exception:
                                s = chunk.decode('latin-1', errors='replace')
                            # replace buffer with chunk and refresh view
                            self.buffer = s
                            # hide results
                            self._results_frame.pack_forget()
                            self.refresh_view()
                            # highlight and go to match inside view
                            self.text.configure(state='normal')
                            self.clear_highlight()
                            self.highlight_matches(self.search_var.get().strip())
                            self.text.configure(state='disabled')
                            return
                        count += 1
                        p = p + len(term)
        except Exception:
            pass

    def perform_search_full(self):
        term = self.search_var.get().strip()
        if not term:
            self.search_status.set('Ingrese término de búsqueda')
            return
        if not (self.use_cache and self.cache_path and os.path.exists(self.cache_path)):
            self.search_status.set('No hay archivo cache para buscar. Activa caché o espera a que se genere.')
            return
        # start search in file immediately
        if self._search_thread and self._search_thread.is_alive():
            self.search_status.set('Búsqueda ya en curso...')
            return
        self.search_status.set('Buscando en archivo completo...')
        self._search_thread = threading.Thread(target=self._search_in_file, args=(term,), daemon=True)
        self._search_thread.start()
        self._poll_search()

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
