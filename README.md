# Suricata-правила для обнаружения Medusa Mythic C2 (HTTP C2 Profile)

Сигнатуры Suricata, которые обнаруживают обмен агента **Medusa** с сервером **Mythic C2** по **HTTP C2 Profile**. Правила основаны на структуре протокола Mythic (сообщение начинается с `base64(UUID)`), а не на URI, User-Agent или командах, поэтому работают на разных конфигурациях профиля.

**Результат:** на трёх записях Medusa (102 HTTP-сессии) алерт на 102 из 102 (311 алертов), на легитимном HTTP - 0 алертов. Подробности, анализ признаков, покрытие, FP/FN - в [report.md](report.md).

## Содержимое

| Путь | Что это |
|---|---|
| `medusa_mythic_http.rules` | 5 правил Suricata (SID 9100001–9100005) |
| `report.md` | отчёт: стенд, анализ трафика, логика правил, проверка |
| `pcaps/medusa_session3.{1,2,3}.pcap` | три записи Medusa с разными конфигурациями payload |
| `pcaps/medusa_all.pcap` | объединённый дамп (2526 пакетов, 102 HTTP-сессии) |
| `logs/fast.log`, `logs/eve.json` | результат прогона правил на `medusa_all.pcap` |
| `logs/dalton_alerts.png`, `logs/dalton_without_alerts.png` | скриншоты Dalton: трафик Medusa и легитимный трафик |
| `logs/legit_traffic.pcap` | легитимный HTTP-трафик для проверки ложных срабатываний |

## Запуск

```
# проверка синтаксиса
suricata -T -S medusa_mythic_http.rules -c /etc/suricata/suricata.yaml

# прогон по трафику Medusa
mkdir -p out && suricata -r pcaps/medusa_all.pcap -S medusa_mythic_http.rules -l out -k none \
        -c /etc/suricata/suricata.yaml --set unix-command.enabled=no
grep -o '\[1:[0-9]*:1\]' out/fast.log | sort | uniq -c     # ожидаемо: 95 / 7 / 102 / 102 / 5

# прогон по легитимному трафику (ожидаемо: пустой fast.log)
mkdir -p out_fp && suricata -r logs/legit_traffic.pcap -S medusa_mythic_http.rules -l out_fp -k none \
        -c /etc/suricata/suricata.yaml --set unix-command.enabled=no
```

**Dalton:** движок Suricata 7.0.14 -> загрузить pcap -> вставить содержимое `medusa_mythic_http.rules` на вкладке Custom Rules -> Submit.
