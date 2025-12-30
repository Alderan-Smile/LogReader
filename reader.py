import threading
import requests
from requests.exceptions import SSLError
import time
import re


class LogReaderThread(threading.Thread):
    def __init__(self, url, update_callback, interval=1.0, proxies=None, verify=True, prompt_callback=None, auto_accept_ssl=False, tail_bytes=65536):
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
        self.tail_bytes = int(tail_bytes or 0)
        self._initial_loaded = False

    def run(self):
        while not self._stop_event.is_set():
            self._pause_event.wait()
            try:
                headers = {}
                # For first load, try to request only the tail to avoid downloading huge files
                if not self._initial_loaded and self.tail_bytes > 0:
                    headers['Range'] = f'bytes=-{self.tail_bytes}'
                # Subsequent requests use the current position to fetch new bytes
                elif self._pos > 0:
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
                except SSLError:
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
                    # mark initial as loaded after a successful response
                    if not self._initial_loaded:
                        self._initial_loaded = True
                        # Try to set absolute position from Content-Range if present
                        cr = resp.headers.get('Content-Range')
                        if cr:
                            m = re.match(r'bytes (\d+)-(\d+)/(\d+|\*)', cr)
                            if m:
                                start = int(m.group(1))
                                end = int(m.group(2))
                                # set position to end+1 (absolute file offset)
                                self._pos = end + 1
                            else:
                                # fallback: use length
                                self._pos = len(content)
                        else:
                            # no Content-Range -> treat as snapshot/full content
                            self._pos = len(content)

                        self._last_content = content
                        self.update_callback(content.decode('utf-8', errors='replace'), replace=True)
                        time.sleep(self.interval)
                        continue

                    # If server responded with partial content (206) append
                    if resp.status_code == 206:
                        cr = resp.headers.get('Content-Range')
                        if cr:
                            m = re.match(r'bytes (\d+)-(\d+)/(\d+|\*)', cr)
                            if m:
                                start = int(m.group(1))
                                end = int(m.group(2))
                                # set absolute pos to end+1
                                self._pos = end + 1
                            else:
                                # fallback to increment
                                self._pos += len(content)
                        else:
                            self._pos += len(content)

                        if content:
                            self.update_callback(content.decode('utf-8', errors='replace'))
                    else:
                        # 200 OK: server may not support Range. Try to detect new bytes without duplicating or reordering
                        if not self._last_content:
                            # No previous content known -> replace whole view
                            self._pos = len(content)
                            self._last_content = content
                            self.update_callback(content.decode('utf-8', errors='replace'), replace=True)
                        else:
                            # Try to find previous buffer inside the returned full content
                            try:
                                idx = content.find(self._last_content)
                            except Exception:
                                idx = -1
                            if idx != -1:
                                # previous buffer found inside content; new data (if any) is after it
                                new_start = idx + len(self._last_content)
                                if new_start < len(content):
                                    new_part = content[new_start:]
                                    self._pos = len(content)
                                    self._last_content = content
                                    self.update_callback(new_part.decode('utf-8', errors='replace'))
                                else:
                                    # no new bytes
                                    self._pos = len(content)
                                    self._last_content = content
                            else:
                                # previous content not found -> likely rotated/truncated; replace all
                                self._pos = len(content)
                                self._last_content = content
                                self.update_callback(content.decode('utf-8', errors='replace'), replace=True)

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
