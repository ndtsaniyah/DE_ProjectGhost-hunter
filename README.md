# Detection Engineer for Project Ghost-Hunter

# 🛡️ Ghost-Hunter: Detection Engineering & Defense Automation Lab
Repositori ini mendokumentasikan seluruh artefak teknis, logika deteksi, dan skrip otomatisasi mitigasi yang saya kembangkan sebagai **Detection Engineer** dalam proyek *Ghost-Hunter*. Fokus utama dari peran saya adalah mengubah telemetri mentah (log host & jaringan) menjadi aturan deteksi proaktif (*custom rules*) serta mengotomatisasikan triase insiden menggunakan Python.

---

## 🎯 Fokus Peran & Komponen Utama

Dalam proyek ini, saya bertanggung jawab penuh atas arsitektur pertahanan berbasis aturan dengan fokus utama:
1. **Analisis Struktur Log Mentah (Raw Field Mapping):** Memetakan parameter krusial dari Sysmon, Windows GPO, dan Zeek DNS logs di Kibana.
2. **Rekayasa Aturan Deteksi (Custom Rules Engineering):** Membangun aturan deteksi berbasis ekspresi reguler (Regex) dengan skema format **Wazuh Rules** dan **Sigma Rules**.
3. **Otomatisasi Triase Insiden (AI-Powered Triage):** Mengembangkan skrip Python untuk memperkaya konteks analisis sesaat setelah alert terpicu di SIEM.
4. **Remediasi & Pengerasan Sistem (System Hardening):** Menyusun rekomendasi mitigasi konkret untuk membatasi ruang gerak penyerang.

---

## 🏗️ Peta Telemetri & Log Mentah (Target Deteksi)

Berikut adalah field spesifik yang saya petakan di lingkungan pengembangan untuk mendeteksi taktik *Living off the Land* (LotL) dan *DNS Tunneling*:

### 1. Host Logs (Sysmon Event ID 1 & PowerShell Event ID 4104)
* **`data.win.eventdata.commandLine`** / **`winlog.event_data.CommandLine`**: Digunakan untuk memfilter eksekusi `schtasks.exe` dan pendeteksian parameter obfuscation (seperti `-enc`, `-encodedcommand`, atau string Base64).
* **`data.win.eventdata.scriptBlockText`**: Digunakan untuk menangkap blok kode penuh hasil dekripsi PowerShell di memori.

### 2. Network Logs (Zeek dns.log via Kibana)
* **`data.zeek.dns.query`** / **`dns.question.name`**: Target analisis string kueri subdomain yang panjang (indikasi DGA atau eksfiltrasi `dnscat2`).
* **`data.zeek.dns.qtype_name`**: Pemantauan khusus untuk tipe record **TXT** anomali yang sering digunakan sebagai jalur C2 outbound.

---

## 🛠️ Taksonomi Aturan Kustom (Wazuh Custom Rules Matrix)

Saya menerapkan standardisasi ID aturan kustom pada rentang **100001 - 100010** di dalam file `wazuh_rules.xml` untuk memisahkan kategori deteksi secara terstruktur:

| Rule ID | Komponen Target | Level | Mitre ATT&CK | Deskripsi Deteksi |
| :--- | :--- | :--- | :--- | :--- |
| **100001 - 100005** | **Host Log** (Sysmon/GPO) | Level 12 (High) | T1053.005 / T1059.001 | Mendeteksi pembuatan Scheduled Task mencurigakan, aktivitas kata kunci `AtomicTest`, dan bypass eksekusi PowerShell terkompresi. |
| **100006 - 100010** | **Network Log** (Zeek DNS) | Level 10 (Medium) | T1071.004 | Mendeteksi anomali panjang kueri subdomain, frekuensi kueri tinggi, dan penyalahgunaan DNS TXT record oleh `dnscat2`. |

---

## 📆 Rencana Pelaksanaan & To-Do List (Spesifik Peran)

### 🔹 Minggu 1: Analisis Telemetri & Perancangan Draf Aturan
* [x] Mempelajari dan memetakan struktur bidang data mentah (*raw log fields*) hasil pengetatan GPO, Sysmon (ID 1 & 4104), dan Zeek dns.log pada Kibana.
* [x] Menyiapkan lingkungan kerja lokal di **VS Code** dengan ekstensi XML/YAML untuk standardisasi penulisan aturan pertahanan.
* [x] Merancang draf awal logika deteksi (*rule blueprint*) berbasis ekspresi reguler (Regex) untuk menangkap parameter mencurigakan.

### 🔹 Minggu 2: Implemetasi Kode Deteksi Kustom & Otomatisasi
* [ ] Mengamati karakteristik log anomali yang berhasil diisolasi di ELK/Kibana pasca eksekusi simulasi serangan oleh tim.
* [ ] Menulis kode **Custom Detection Rules** (`.xml` & `.yml`) di VS Code menggunakan variabel field asli sesuai taksonomi ID kelompok.
* [ ] Mengembangkan draf awal skrip otomatisasi analisis insiden berbasis AI menggunakan **Python** untuk memproses alert kustom secara otomatis.

### 🔹 Minggu 3: Finalisasi, Pengujian, & Penyusunan Dokumen Mitigasi
* [ ] Mengunggah (*upload*) dan menguji (*testing*) *Custom Detection Rules* ke dalam server Wazuh Manager untuk memastikan bebas dari *syntax error*.
* [ ] Mengintegrasikan dan mendemonstrasikan skrip **AI-Powered Incident Analyst (Python)** untuk melakukan pengayaan analisis otomatis (*automated triage*) saat alert terpicu di SIEM.
* [ ] Menyusun dokumen rekomendasi mitigasi konkret untuk pengerasan sistem (*system hardening*), seperti pembatasan hak akses `schtasks.exe` dan pemblokiran kueri DNS TXT yang tidak sah.

---

## 📁 Struktur Repositori (Detection Engineer Workspace)

```text
├── .vscode/                  # Konfigurasi workspace lokal VS Code
├── rules/
│   ├── wazuh_rules.xml       # File aturan kustom Wazuh kelompok (ID: 100001-100010)
│   └── sigma_rules.yml       # Draf aturan portabel berbasis format Sigma
├── scripts/
│   └── ai_triage_analyst.py  # Skrip Python AI untuk otomatisasi pengayaan alert kustom
└── docs/
    ├── raw_fields_mapping.md # Dokumentasi hasil pemetaan field Sysmon & Zeek di Kibana
    └── remediation_guide.md  # Dokumen rekomendasi taktis pengerasan sistem (Mitigasi)
