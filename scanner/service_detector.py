import socket

class ServiceDetector:
    COMMON = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
              110:"POP3",143:"IMAP",443:"HTTPS",3306:"MySQL",3389:"RDP",
              5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-Proxy"}

    def __init__(self, target, timeout=1.0):
        self.target = target
        self.timeout = timeout

    def detect(self, ports):
        services = {}
        for port in ports:
            banner = self._grab(port).lower()
            if "ssh" in banner: name = "SSH"
            elif "ftp" in banner: name = "FTP"
            elif "apache" in banner: name = "HTTP (Apache)"
            elif "nginx" in banner: name = "HTTP (Nginx)"
            elif "mysql" in banner: name = "MySQL"
            else: name = self.COMMON.get(port, "Unknown")
            services[port] = {"name": name, "banner": banner[:100] if banner else "No banner"}
        return services

    def _grab(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, port))
            if port in (80, 443, 8080, 8443):
                s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            b = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return b
        except:
            return ""
