import socket, threading
from queue import Queue

class PortScanner:
    def __init__(self, target, port_range, threads=50, timeout=1.0):
        self.target = target
        self.port_range = port_range
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
        self.queue = Queue()

    def scan(self):
        ports = []
        for part in self.port_range.split(","):
            if "-" in part:
                s, e = part.split("-")
                ports.extend(range(int(s), int(e) + 1))
            else:
                ports.append(int(part))

        for p in ports:
            self.queue.put(p)

        for _ in range(min(self.threads, len(ports))):
            t = threading.Thread(target=self._worker)
            t.start()

        self.queue.join()
        return sorted(self.open_ports)

    def _worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((self.target, port)) == 0:
                    self.open_ports.append(port)
                s.close()
            except:
                pass
            self.queue.task_done()
