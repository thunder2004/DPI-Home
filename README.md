# 🛡️ DPI Home

**Анализатор трафика MikroTik в реальном времени**

Приложение для Windows 10, которое подключается к **MikroTik Packet Sniffer** и анализирует трафик в реальном времени, выявляя потенциально опасные подключения и аномалии.

## 🚀 Возможности

- **Захват трафика** — прямое подключение к MikroTik Packet Sniffer (TCP raw stream)
- **Глубокий анализ пакетов (DPI)** — парсинг Ethernet/IP/TCP/UDP заголовков
- **Сигнатурный анализ** — обнаружение известных угроз (EternalBlue, SQLi, XSS, сканирование портов и др.)
- **Поведенческий анализ** — выявление port scan, brute-force атак, DNS/ICMP туннелирования
- **Красивый GUI** — тёмная тема Material Design, real-time обновление статистики
- **Градация угроз** — Info / Low / Medium / High / Critical

## 🔧 Технологии

| Компонент | Технология |
|-----------|------------|
| Язык | C# 12 (.NET 8) |
| GUI | WPF + MaterialDesignInXaml |
| MVVM | CommunityToolkit.Mvvm |
| Парсинг | Нативный (без сторонних библиотек) |
| Производительность | System.IO.Pipelines, ConcurrentDictionary, lock-free счётчики |

## 📋 Сигнатуры угроз

| Угроза | Уровень | Описание |
|--------|---------|----------|
| NULL Scan | 🔴 High | TCP с нулевыми флагами |
| XMAS Scan | 🔴 High | FIN+PSH+URG флаги |
| FIN Scan | ⚡ Medium | Только FIN флаг |
| EternalBlue | 💀 Critical | SMBv1 эксплойт (MS17-010) |
| SQL Injection | 🔴 High | SQL-инъекция в HTTP |
| XSS | ⚡ Medium | Cross-site scripting |
| DNS Tunneling | 🔴 High | Длинные DNS-запросы |
| ICMP Tunneling | 🔴 High | Крупные ICMP-пакеты |
| RDP Brute Force | 🔴 High | Подозрительная RDP активность |
| WinBox Exploit | 💀 Critical | CVE-2018-14847 |
| Port Scan | 🔴 High | Поведенческий анализ |
| Brute Force | 💀 Critical | Поведенческий анализ |

## 🖥️ Системные требования

- Windows 10 / 11
- .NET 8 Runtime
- MikroTik RouterOS с включённым Packet Sniffer

## 🔌 Настройка MikroTik

```bash
# Включить Packet Sniffer на MikroTik
/tool sniffer start
/tool sniffer set streaming-enabled=yes streaming-server=192.168.x.x:2000
```

## 🏗️ Сборка

```bash
dotnet restore
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained true
```

## 📄 Лицензия

MIT
