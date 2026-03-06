import socket
import threading
from datetime import datetime

class SimpleScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                print(f"[+] Порт {port} открыт")
            sock.close()
        except:
            pass
    
    def scan_range(self, start_port, end_port):
        print(f"\n[*] Сканирование {self.target} (порты {start_port}-{end_port})")
        print(f"[*] Начато: {datetime.now().strftime('%H:%M:%S')}\n")
        
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
         
            if len(threads) % 50 == 0:
                for t in threads:
                    t.join()
                threads = []
        
  
        for thread in threads:
            thread.join()
        
        self.show_results()
    
    def scan_popular(self):
        popular_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080]
        print(f"\n[*] Сканирование популярных портов на {self.target}\n")
        
        for port in popular_ports:
            self.scan_port(port)
        
        self.show_results()
    
    def show_results(self):
        print("\n" + "="*50)
        print(f"РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ: {self.target}")
        print("="*50)
        
        if self.open_ports:
            print(f"\nНайдено открытых портов: {len(self.open_ports)}")
            print("\nОткрытые порты:")
            for port in sorted(self.open_ports):
                service = self.get_service(port)
                print(f"  Порт {port:5d} - {service}")
        else:
            print("\nОткрытые порты не найдены")
        
        print("="*50)
    
    def get_service(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
        }
        return services.get(port, "Unknown")
    
    def save_results(self, filename="scan_results.txt"):
        with open(filename, 'w') as f:
            f.write(f"Scan Results for {self.target}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write(f"Open ports: {len(self.open_ports)}\n\n")
            for port in sorted(self.open_ports):
                f.write(f"Port {port} - {self.get_service(port)}\n")
        print(f"\n[+] Результаты сохранены в {filename}")


def main():
    
  
    target = input("\nВведите IP адрес или хост: ").strip()
    
  
    print("\nВыберите тип сканирования:")
    print("1. Популярные порты (быстро)")
    print("2. Диапазон портов")
    print("3. Все порты 1-1024 (медленно)")
    
    choice = input("\nВаш выбор (1-3): ").strip()
    
    scanner = SimpleScanner(target)
    
    if choice == "1":
        scanner.scan_popular()
    elif choice == "2":
        start = int(input("Начальный порт: "))
        end = int(input("Конечный порт: "))
        scanner.scan_range(start, end)
    elif choice == "3":
        scanner.scan_range(1, 1024)
    else:
        print("Неверный выбор!")
        return
    

    save = input("\nСохранить результаты? (y/n): ").strip().lower()
    if save == 'y':
        scanner.save_results()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Сканирование прервано пользователем")
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")