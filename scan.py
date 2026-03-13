import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import json
import subprocess
import re
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor


class GeoIPLookup:
    """Класс для определения геолокации по IP"""
    
    def __init__(self):
        self.cache = {}
        self.api_urls = [
            "http://ip-api.com/json/",
            "http://ipapi.co/{}/json/",
        ]
    
    def get_location(self, ip):
        """Получение информации о местоположении IP"""
        # Проверяем кэш
        if ip in self.cache:
            return self.cache[ip]
        
        # Локальные адреса
        if ip in ['127.0.0.1', 'localhost']:
            info = {
                'country': 'Local',
                'city': 'Localhost',
                'org': 'Local Machine',
                'isp': 'Local',
                'status': 'success'
            }
            self.cache[ip] = info
            return info
        
        # Приватные IP
        if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', 
                          '172.18.', '172.19.', '172.20.', '172.21.',
                          '172.22.', '172.23.', '172.24.', '172.25.',
                          '172.26.', '172.27.', '172.28.', '172.29.',
                          '172.30.', '172.31.')):
            info = {
                'country': 'Private Network',
                'city': 'Local Network',
                'org': 'Private IP',
                'isp': 'Local Network',
                'status': 'success'
            }
            self.cache[ip] = info
            return info
        
        # Пробуем API
        for api_url in self.api_urls:
            try:
                if '{}' in api_url:
                    url = api_url.format(ip)
                else:
                    url = api_url + ip
                
                response = requests.get(url, timeout=3)
                data = response.json()
                
                if data.get('status') == 'success':
                    info = {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'org': data.get('org', data.get('isp', 'Unknown')),
                        'isp': data.get('isp', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'zip': data.get('zip', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown'),
                        'status': 'success'
                    }
                    self.cache[ip] = info
                    return info
                    
            except:
                continue
        
        # Если все API не сработали
        info = {
            'country': 'Unknown',
            'city': 'Unknown',
            'org': 'Unknown',
            'isp': 'Unknown',
            'status': 'error'
        }
        self.cache[ip] = info
        return info


class NetworkScanner:
    """Класс для сканирования сети и обнаружения атак"""
    
    def __init__(self):
        self.scanning = False
        self.results = []
        self.suspicious_ips = defaultdict(lambda: {
            'count': 0, 
            'ports': set(), 
            'first_seen': None, 
            'last_seen': None,
            'total_bytes': 0,  # Общий объем трафика
            'packet_sizes': [],  # Размеры пакетов
            'protocols': defaultdict(int),
            'flags': defaultdict(int),
            'icmp_count': 0,  # Количество ping (ICMP)
            'tcp_count': 0,
            'udp_count': 0
        })
        self.blocked_ips = set()
        self.connection_lock = threading.Lock()
        self.progress_callback = None
        self.current_port = 0
        self.total_ports = 0
        self.geo_lookup = GeoIPLookup()
        self.total_packets = 0
        self.total_bytes = 0
        
    def scan_port(self, ip, port, timeout=0.5):
        """Сканирование одного порта"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                return {
                    'ip': ip,
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            sock.close()
        except:
            pass
        return None
    
    def scan_ip_ports(self, ip, start_port=1, end_port=1000, threads=50):
        """Многопоточное сканирование портов"""
        open_ports = []
        self.current_port = start_port
        self.total_ports = end_port - start_port + 1
        
        def worker(ports_to_scan):
            for port in ports_to_scan:
                result = self.scan_port(ip, port)
                if result:
                    with self.connection_lock:
                        open_ports.append(result)
                with self.connection_lock:
                    self.current_port = port
                    if self.progress_callback:
                        self.progress_callback(self.current_port, self.total_ports)
        
        ports = list(range(start_port, end_port + 1))
        chunk_size = len(ports) // threads + 1
        
        thread_list = []
        for i in range(threads):
            start_idx = i * chunk_size
            end_idx = min((i + 1) * chunk_size, len(ports))
            if start_idx < len(ports):
                port_chunk = ports[start_idx:end_idx]
                t = threading.Thread(target=worker, args=(port_chunk,))
                thread_list.append(t)
                t.start()
        
        for t in thread_list:
            t.join()
        
        return open_ports
    
    def get_mac_address(self, ip):
        """Получение MAC-адреса"""
        try:
            if os.name == 'nt':
                output = subprocess.check_output(['arp', '-a', ip], stderr=subprocess.STDOUT)
                output = output.decode('utf-8', errors='ignore')
                match = re.search(r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}', output)
                if match:
                    return match.group(0).replace('-', ':')
            else:
                output = subprocess.check_output(['arp', '-n', ip], stderr=subprocess.STDOUT)
                output = output.decode('utf-8', errors='ignore')
                parts = output.split()
                for part in parts:
                    if re.match(r'[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}', part, re.I):
                        return part
        except:
            pass
        return "N/A"
    
    def get_host_info(self, ip):
        """Получение информации о хосте"""
        info = {
            'ip': ip,
            'hostname': 'N/A',
            'mac': self.get_mac_address(ip),
            'country': 'N/A',
            'provider': 'N/A'
        }
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            info['hostname'] = hostname
        except:
            pass
        
        return info
    
    def detect_ddos_packet(self, packet):
        """Обработка пакета для обнаружения DDoS атак с учетом объема"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Считаем размер пакета
            packet_size = len(packet)
            
            with self.connection_lock:
                self.total_packets += 1
                self.total_bytes += packet_size
                
                if src_ip not in self.suspicious_ips:
                    self.suspicious_ips[src_ip] = {
                        'count': 0,
                        'ports': set(),
                        'first_seen': datetime.now(),
                        'last_seen': datetime.now(),
                        'protocols': defaultdict(int),
                        'flags': defaultdict(int),
                        'total_bytes': 0,
                        'packet_sizes': [],
                        'icmp_count': 0,
                        'tcp_count': 0,
                        'udp_count': 0,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    }
                
                ip_data = self.suspicious_ips[src_ip]
                ip_data['count'] += 1
                ip_data['last_seen'] = datetime.now()
                ip_data['total_bytes'] += packet_size
                ip_data['packet_sizes'].append(packet_size)
                
                # Ограничиваем хранение размеров пакетов (последние 100)
                if len(ip_data['packet_sizes']) > 100:
                    ip_data['packet_sizes'] = ip_data['packet_sizes'][-100:]
                
                # Определяем тип трафика
                if ICMP in packet:
                    ip_data['protocols']['ICMP'] += 1
                    ip_data['icmp_count'] += 1
                    # Проверяем это ping (ICMP Echo Request)
                    if packet[ICMP].type == 8:
                        ip_data['is_ping'] = True
                    
                elif TCP in packet:
                    ip_data['protocols']['TCP'] += 1
                    ip_data['tcp_count'] += 1
                    ip_data['flags'][str(packet[TCP].flags)] += 1
                    ip_data['ports'].add(packet[TCP].dport)
                    
                elif UDP in packet:
                    ip_data['protocols']['UDP'] += 1
                    ip_data['udp_count'] += 1
                    ip_data['ports'].add(packet[UDP].dport)
    
    def get_ip_location(self, ip):
        """Получение геолокации для IP"""
        return self.geo_lookup.get_location(ip)
    
    def get_suspicious_ips_list(self, threshold=10):
        """Получение списка подозрительных IP с объемом трафика"""
        suspicious = []
        current_time = datetime.now()
        
        for ip, data in self.suspicious_ips.items():
            time_diff = (current_time - data['first_seen']).total_seconds()
            
            # Вычисляем средний размер пакета
            avg_packet_size = sum(data['packet_sizes']) / len(data['packet_sizes']) if data['packet_sizes'] else 0
            
            # Вычисляем скорость (пакетов в секунду)
            packets_per_second = data['count'] / time_diff if time_diff > 0 else 0
            
            # Вычисляем объем трафика в секунду
            bytes_per_second = data['total_bytes'] / time_diff if time_diff > 0 else 0
            
            # Определяем подозрительность
            is_suspicious = (
                data['count'] > threshold or 
                len(data['ports']) > 3 or
                packets_per_second > 2 or
                data['total_bytes'] > 10000 or  # Больше 10KB
                data['icmp_count'] > 20  # Много ping запросов
            )
            
            if is_suspicious:
                # Определяем тип атаки
                attack_type = "Unknown"
                if data['icmp_count'] > data['count'] * 0.8:
                    attack_type = "ICMP Flood (Ping)"
                elif data['tcp_count'] > data['count'] * 0.8:
                    attack_type = "TCP Flood"
                elif data['udp_count'] > data['count'] * 0.8:
                    attack_type = "UDP Flood"
                elif len(data['ports']) > 10:
                    attack_type = "Port Scanning"
                
                # Получаем геолокацию
                location = self.get_ip_location(ip)
                
                suspicious.append({
                    'ip': ip,
                    'packet_count': data['count'],
                    'ports_scanned': len(data['ports']),
                    'total_bytes': data['total_bytes'],
                    'avg_packet_size': int(avg_packet_size),
                    'bytes_per_second': int(bytes_per_second),
                    'first_seen': data['first_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    'last_seen': data['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    'protocols': dict(data['protocols']),
                    'threat_level': 'HIGH' if data['count'] > 50 or data['total_bytes'] > 50000 else 'MEDIUM',
                    'country': location.get('country', 'Unknown'),
                    'city': location.get('city', 'Unknown'),
                    'isp': location.get('isp', 'Unknown'),
                    'attack_type': attack_type,
                    'is_ping': data.get('is_ping', False)
                })
        
        return sorted(suspicious, key=lambda x: (x['packet_count'], x['total_bytes']), reverse=True)
    
    def get_traffic_stats(self):
        """Получение общей статистики трафика"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'total_mb': round(self.total_bytes / (1024 * 1024), 2),
            'unique_ips': len(self.suspicious_ips),
            'suspicious_count': len(self.get_suspicious_ips_list())
        }
    
    def block_ip(self, ip):
        """Блокировка IP адреса"""
        try:
            if os.name == 'nt':
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True)
            else:
                cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
            
            self.blocked_ips.add(ip)
            return True, f"IP {ip} заблокирован"
        except Exception as e:
            return False, f"Ошибка блокировки: {str(e)}"
    
    def unblock_ip(self, ip):
        """Разблокировка IP адреса"""
        try:
            if os.name == 'nt':
                cmd = f'netsh advfirewall firewall delete rule name="Block_{ip}"'
                subprocess.run(cmd, shell=True, check=True)
            else:
                cmd = f'sudo iptables -D INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
            
            self.blocked_ips.discard(ip)
            return True, f"IP {ip} разблокирован"
        except Exception as e:
            return False, f"Ошибка разблокировки: {str(e)}"
    
    def save_to_json(self, filename, data):
        """Сохранение результатов в JSON"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            return True
        except:
            return False


class ScannerGUI:
    """Графический интерфейс приложения"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner - DDoS Detection & IP Blocker")
        self.root.geometry("1600x900")
        self.root.configure(bg='#f0f0f0')
        
        self.scanner = NetworkScanner()
        self.sniffing = False
        self.sniff_thread = None
        self.scan_animation_active = False
        
        self.setup_ui()
    
    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        # Верхняя панель с кнопками
        top_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        top_frame.pack_propagate(False)
        
        # Кнопки управления
        self.start_scan_btn = tk.Button(top_frame, text="🔍 Начать сканирование", 
                                        command=self.start_scan,
                                        bg='#3498db', fg='white', relief='flat', 
                                        padx=15, pady=8, font=('Arial', 9, 'bold'))
        self.start_scan_btn.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.stop_scan_btn = tk.Button(top_frame, text="⏹ Остановить", 
                                       command=self.stop_scan,
                                       bg='#e74c3c', fg='white', relief='flat', 
                                       padx=15, pady=8, font=('Arial', 9, 'bold'))
        self.stop_scan_btn.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.start_sniff_btn = tk.Button(top_frame, text="📡 Захват трафика", 
                                         command=self.toggle_sniffing,
                                         bg='#3498db', fg='white', relief='flat', 
                                         padx=15, pady=8, font=('Arial', 9, 'bold'))
        self.start_sniff_btn.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.stats_btn = tk.Button(top_frame, text="📊 Статистика", 
                                   command=self.show_traffic_stats,
                                   bg='#95a5a6', fg='white', relief='flat', 
                                   padx=15, pady=8, font=('Arial', 9, 'bold'))
        self.stats_btn.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.block_btn = tk.Button(top_frame, text="🚫 Заблокировать IP", 
                                   command=self.block_selected_ip,
                                   bg='#e67e22', fg='white', relief='flat', 
                                   padx=15, pady=8, font=('Arial', 9, 'bold'))
        self.block_btn.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.unblock_btn = tk.Button(top_frame, text="✅ Разблокировать IP", 
                                     command=self.unblock_selected_ip,
                                     bg='#27ae60', fg='white', relief='flat', 
                                     padx=15, pady=8, font=('Arial', 9, 'bold'))
        self.unblock_btn.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.save_btn = tk.Button(top_frame, text="💾 Сохранить JSON", 
                                  command=self.save_results,
                                  bg='#9b59b6', fg='white', relief='flat', 
                                  padx=15, pady=8, font=('Arial', 9, 'bold'))
        self.save_btn.pack(side=tk.LEFT, padx=5, pady=10)
        
        # Поля ввода
        input_frame = tk.Frame(top_frame, bg='#2c3e50')
        input_frame.pack(side=tk.RIGHT, padx=20)
        
        tk.Label(input_frame, text="IP:", bg='#2c3e50', fg='white', font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(input_frame, width=15, font=('Arial', 9))
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(input_frame, text="Порты:", bg='#2c3e50', fg='white', font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=(15,5))
        self.port_start = tk.Entry(input_frame, width=5, font=('Arial', 9))
        self.port_start.insert(0, "1")
        self.port_start.pack(side=tk.LEFT)
        tk.Label(input_frame, text="-", bg='#2c3e50', fg='white').pack(side=tk.LEFT)
        self.port_end = tk.Entry(input_frame, width=5, font=('Arial', 9))
        self.port_end.insert(0, "1000")
        self.port_end.pack(side=tk.LEFT)
        
        # Панель прогресса сканирования
        progress_frame = tk.Frame(self.root, bg='#ecf0f1', height=40)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        progress_frame.pack_propagate(False)
        
        self.progress_label = tk.Label(progress_frame, text="Готов к сканированию", 
                                       bg='#ecf0f1', fg='#2c3e50', font=('Arial', 10, 'bold'))
        self.progress_label.pack(side=tk.LEFT, padx=10)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=600)
        self.progress_bar.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.progress_value_label = tk.Label(progress_frame, text="0%", 
                                             bg='#ecf0f1', fg='#2c3e50', 
                                             font=('Arial', 10, 'bold'), width=6)
        self.progress_value_label.pack(side=tk.LEFT, padx=10)
        
        # Индикатор активности (мигающий)
        self.activity_indicator = tk.Label(progress_frame, text="●", 
                                           bg='#ecf0f1', fg='#95a5a6', 
                                           font=('Arial', 16, 'bold'))
        self.activity_indicator.pack(side=tk.LEFT, padx=10)
        
        # Основная область с тремя таблицами
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.create_table_section(main_frame, "Все IP-адреса", 0)
        self.create_table_section(main_frame, "Подозрительные IP (DDoS)", 1)
        self.create_table_section(main_frame, "Заблокированные IP", 2)
        
        # Статус бар
        self.status_var = tk.StringVar()
        self.status_var.set("✓ Готов к работе | Захват трафика: выключен")
        status_bar = tk.Label(self.root, textvariable=self.status_var, 
                             bd=1, relief=tk.SUNKEN, anchor=tk.W, bg='#2c3e50', fg='white',
                             font=('Arial', 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def show_traffic_stats(self):
        """Показать расширенную статистику трафика"""
        stats = self.scanner.get_traffic_stats()
        
        # Получаем топ IP
        suspicious = self.scanner.get_suspicious_ips_list()
        
        stats_text = f"""
        📊 РАСШИРЕННАЯ СТАТИСТИКА ТРАФИКА
        
        💾 Общий объем:
        • Пакетов всего: {stats['total_packets']}
        • Байт всего: {stats['total_bytes']:,} ({stats['total_mb']} MB)
        • Уникальных IP: {stats['unique_ips']}
        • Подозрительных: {stats['suspicious_count']}
        
        """
        
        if suspicious:
            stats_text += "🎯 ТОП-5 подозрительных IP:\n\n"
            for i, ip_data in enumerate(suspicious[:5], 1):
                ping_mark = "🏓 PING" if ip_data.get('is_ping') else ""
                stats_text += f"""{i}. {ip_data['ip']} {ping_mark}
   Страна: {ip_data['country']}, {ip_data['city']}
   Пакетов: {ip_data['packet_count']}, Объем: {ip_data['total_bytes']:,} байт
   Скорость: {ip_data['bytes_per_second']:,} байт/сек
   Атака: {ip_data['attack_type']}
   Угроза: {ip_data['threat_level']}

"""
        else:
            stats_text += " Подозрительных IP пока нет\n"
        
        messagebox.showinfo("📊 Статистика трафика", stats_text)
    
    def create_table_section(self, parent, title, table_id):
        """Создание секции с таблицей"""
        frame = tk.LabelFrame(parent, text=title, bg='#ecf0f1', padx=5, pady=5, 
                             font=('Arial', 10, 'bold'))
        frame.grid(row=table_id // 2, column=table_id % 2, sticky='nsew', padx=5, pady=5)
        
        parent.grid_rowconfigure(table_id // 2, weight=1)
        parent.grid_columnconfigure(table_id % 2, weight=1)
        
        if table_id == 0:
            columns = ('ip', 'hostname', 'mac', 'ports', 'services', 'timestamp')
            col_widths = (120, 150, 120, 100, 150, 140)
            headings = ('IP адрес', 'Hostname', 'MAC адрес', 'Портов', 'Сервисы', 'Время')
        elif table_id == 1:
            columns = ('ip', 'country', 'packets', 'bytes', 'bps', 'attack', 'threat', 'ping')
            col_widths = (130, 120, 80, 100, 100, 120, 80, 60)
            headings = ('IP адрес', 'Страна/Город', 'Пакетов', 'Объем (байт)', 'Байт/сек', 'Тип атаки', 'Угроза', 'Ping')
        else:
            columns = ('ip', 'blocked_time', 'reason')
            col_widths = (200, 180, 250)
            headings = ('IP адрес', 'Время блокировки', 'Причина')
        
        tree = ttk.Treeview(frame, columns=columns, show='headings', height=10)
        
        for col, heading, width in zip(columns, headings, col_widths):
            tree.heading(col, text=heading)
            tree.column(col, width=width, minwidth=50)
        
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        
        if table_id == 0:
            self.all_ips_table = tree
        elif table_id == 1:
            self.suspicious_table = tree
        else:
            self.blocked_table = tree
    
    def update_progress(self, current, total):
        """Обновление прогресс-бара"""
        try:
            percentage = min(int((current / total) * 100), 100)
            self.progress_bar['value'] = percentage
            self.progress_value_label.config(text=f"{percentage}%")
            self.progress_label.config(text=f"Сканирование порта {current} из {total}")
            self.root.update_idletasks()
        except:
            pass
    
    def animate_scanning(self):
        """Анимация индикатора активности"""
        if self.scan_animation_active:
            current_color = self.activity_indicator.cget('fg')
            new_color = '#2ecc71' if current_color == '#e74c3c' else '#e74c3c'
            self.activity_indicator.config(fg=new_color)
            self.root.after(500, self.animate_scanning)
    
    def start_scan(self):
        """Запуск сканирования"""
        if self.scanner.scanning:
            messagebox.showwarning("Внимание", "Сканирование уже выполняется")
            return
        
        ip = self.ip_entry.get().strip()
        try:
            start_port = int(self.port_start.get())
            end_port = int(self.port_end.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный диапазон портов")
            return
        
        # Визуальная индикация начала сканирования
        self.scanner.scanning = True
        self.scan_animation_active = True
        self.start_scan_btn.config(bg='#95a5a6', state='disabled')
        self.progress_bar['maximum'] = 100
        self.progress_bar['value'] = 0
        self.progress_label.config(text=f"Начало сканирования {ip}...")
        self.progress_value_label.config(text="0%")
        self.status_var.set(f"⚡ Сканирование {ip} (порты {start_port}-{end_port})...")
        
        # Запуск анимации
        self.animate_scanning()
        
        # Запуск сканирования в потоке
        scan_thread = threading.Thread(target=self._run_scan, args=(ip, start_port, end_port))
        scan_thread.daemon = True
        scan_thread.start()
    
    def _run_scan(self, ip, start_port, end_port):
        """Выполнение сканирования в фоне"""
        try:
            # Устанавливаем callback для обновления прогресса
            self.scanner.progress_callback = self.update_progress
            
            open_ports = self.scanner.scan_ip_ports(ip, start_port, end_port)
            host_info = self.scanner.get_host_info(ip)
            
            if open_ports:
                services = ', '.join(set(p['service'] for p in open_ports))
                self.root.after(0, lambda: self.add_to_all_ips_table(ip, host_info, open_ports, services))
                
            self.root.after(0, lambda: self.status_var.set(
                f"✓ Найдено {len(open_ports)} открытых портов на {ip}"
            ))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Ошибка сканирования", str(e)))
        finally:
            self.scanner.scanning = False
            self.scan_animation_active = False
            self.root.after(0, self.scan_complete)
    
    def scan_complete(self):
        """Завершение сканирования"""
        self.start_scan_btn.config(bg='#3498db', state='normal')
        self.activity_indicator.config(fg='#27ae60')  # Зеленый - готов
        self.progress_label.config(text="✓ Сканирование завершено")
        self.status_var.set("✓ Готов к работе | Сканирование завершено")
        messagebox.showinfo("Готово", "Сканирование завершено!")
    
    def add_to_all_ips_table(self, ip, host_info, open_ports, services):
        """Добавление результата в таблицу всех IP"""
        existing = self.all_ips_table.get_children()
        for item in existing:
            if self.all_ips_table.item(item)['values'][0] == ip:
                self.all_ips_table.delete(item)
                break
        
        self.all_ips_table.insert('', 'end', values=(
            ip,
            host_info['hostname'],
            host_info['mac'],
            len(open_ports),
            services[:50] + '...' if len(services) > 50 else services,
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))
    
    def toggle_sniffing(self):
        """Включение/выключение захвата трафика"""
        if self.sniffing:
            self.stop_sniffing()
        else:
            self.start_sniffing()
    
    def start_sniffing(self):
        """Запуск захвата трафика"""
        try:
            self.sniffing = True
            self.start_sniff_btn.config(text="⏹ Остановить захват", bg='#e74c3c')
            self.status_var.set("📡 Захват трафика АКТИВЕН | Анализ пакетов...")
            self.activity_indicator.config(fg='#e74c3c')  # Красный - активно
            
            self.sniff_thread = threading.Thread(target=self._sniff_packets)
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось начать захват: {e}")
            self.sniffing = False
    
    def _sniff_packets(self):
        """Функция захвата пакетов"""
        try:
            from scapy.all import conf
            
            # Проверяем доступность pcap
            if not conf.use_pcap:
                # Используем L3 socket для Windows без Npcap
                from scapy.all import L3RawSocket
                conf.L3socket = L3RawSocket
            
            # Захватываем пакеты
            sniff(prn=self.scanner.detect_ddos_packet, 
                  store=0, 
                  filter="tcp or udp or icmp", 
                  timeout=300,
                  iface=None)
              
        except PermissionError:
            self.root.after(0, lambda: messagebox.showerror(
                "Ошибка прав доступа", 
                "Запустите программу от имени Администратора!"
            ))
        except Exception as e:
            error_msg = str(e)
            if "winpcap" in error_msg.lower() or "npcap" in error_msg.lower():
                self.root.after(0, lambda: messagebox.showerror(
                    "Требуется Npcap",
                    "Для захвата пакетов необходим Npcap!\n\n"
                    "1. Скачайте: https://npcap.com/\n"
                    "2. Установите с опцией 'WinPcap API-compatible Mode'\n"
                    "3. Перезапустите программу"
                ))
            else:
                self.root.after(0, lambda: messagebox.showerror("Ошибка захвата", f"{error_msg}"))
    
    def stop_sniffing(self):
        """Остановка захвата трафика"""
        self.sniffing = False
        self.start_sniff_btn.config(text="📡 Захват трафика", bg='#3498db')
        self.status_var.set("✓ Готов к работе | Захват трафика остановлен")
        self.activity_indicator.config(fg='#27ae60')
        self.update_suspicious_table()
    
    def update_suspicious_table(self):
        """Обновление таблицы подозрительных IP с геолокацией и объемом"""
        for item in self.suspicious_table.get_children():
            self.suspicious_table.delete(item)
            
        suspicious = self.scanner.get_suspicious_ips_list()
        
        for ip_data in suspicious:
            # Форматируем страну и город
            location = f"{ip_data['country']}, {ip_data['city']}"
            if len(location) > 25:
                location = location[:22] + "..."
            
            # Определяем это ping или нет
            ping_mark = "🏓" if ip_data.get('is_ping') else ""
            
            self.suspicious_table.insert('', 'end', values=(
                ip_data['ip'],
                location,
                ip_data['packet_count'],
                f"{ip_data['total_bytes']:,}",
                f"{ip_data['bytes_per_second']:,}",
                ip_data['attack_type'],
                ip_data['threat_level'],
                ping_mark
            ))
    
    def block_selected_ip(self):
        """Блокировка выбранного IP"""
        selection = self.suspicious_table.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите IP для блокировки")
            return
            
        item = self.suspicious_table.item(selection[0])
        ip = item['values'][0]
        
        success, msg = self.scanner.block_ip(ip)
        
        if success:
            self.blocked_table.insert('', 'end', values=(
                ip,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                f"Подозрительная активность (DDoS) - {item['values'][5]}"
            ))
            self.suspicious_table.delete(selection[0])
            messagebox.showinfo("Успех", msg)
        else:
            messagebox.showerror("Ошибка", msg)
    
    def unblock_selected_ip(self):
        """Разблокировка выбранного IP"""
        selection = self.blocked_table.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите IP для разблокировки")
            return
            
        item = self.blocked_table.item(selection[0])
        ip = item['values'][0]
        
        success, msg = self.scanner.unblock_ip(ip)
        
        if success:
            self.blocked_table.delete(selection[0])
            messagebox.showinfo("Успех", msg)
        else:
            messagebox.showerror("Ошибка", msg)
    
    def stop_scan(self):
        """Остановка сканирования"""
        self.scanner.scanning = False
        self.scan_animation_active = False
        self.status_var.set("⚠ Сканирование остановлено пользователем")
        self.activity_indicator.config(fg='#f39c12')  # Оранжевый - остановлено
    
    def save_results(self):
        """Сохранение результатов в JSON"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if not filename:
            return
            
        data = {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'traffic_stats': self.scanner.get_traffic_stats(),
            'all_ips': [],
            'suspicious_ips': [],
            'blocked_ips': []
        }
        
        for item in self.all_ips_table.get_children():
            values = self.all_ips_table.item(item)['values']
            data['all_ips'].append({
                'ip': values[0],
                'hostname': values[1],
                'mac': values[2],
                'open_ports_count': values[3],
                'services': values[4],
                'timestamp': values[5]
            })
            
        for item in self.suspicious_table.get_children():
            values = self.suspicious_table.item(item)['values']
            data['suspicious_ips'].append({
                'ip': values[0],
                'location': values[1],
                'packet_count': values[2],
                'total_bytes': values[3].replace(',', ''),
                'bytes_per_second': values[4].replace(',', ''),
                'attack_type': values[5],
                'threat_level': values[6],
                'is_ping': values[7] == '🏓'
            })
            
        for item in self.blocked_table.get_children():
            values = self.blocked_table.item(item)['values']
            data['blocked_ips'].append({
                'ip': values[0],
                'blocked_time': values[1],
                'reason': values[2]
            })
            
        if self.scanner.save_to_json(filename, data):
            messagebox.showinfo("Успех", f"Результаты сохранены в {filename}")
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить файл")


def main():
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()