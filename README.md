# 🛡️ Ghost-Hunter: Detection Engineering & Defense Automation Lab

[![Wazuh Rules](https://img.shields.io/badge/Production_Rules-wazuh__rules.xml-orange?style=flat-square&logo=wazuh&logoColor=white)](#-wazuh-rules-production)
[![Sigma Playbook](https://img.shields.io/badge/Portable_Detection-sigma__rules.yml-blue?style=flat-square&logo=sigma&logoColor=white)](#-sigma-playbook)
[![Kibana Queries](https://img.shields.io/badge/Hunting_Queries-query__kibana.txt-005571?style=flat-square&logo=kibana&logoColor=white)](#-kibana-master-queries)


Repositori ini mendokumentasikan seluruh artefak teknis, logika deteksi, dan skrip otomatisasi mitigasi yang saya kembangkan sebagai **Detection Engineer** dalam proyek *Ghost-Hunter*. Fokus utama dari peran ini adalah mentransformasikan telemetri mentah (*host & network logs*) menjadi aturan deteksi proaktif (*custom rules*) serta mengoptimasikan visualisasi triase insiden pada SIEM.

---

## 🎯 Fokus Peran & Komponen Utama

Dalam proyek ini, saya bertanggung jawab penuh atas arsitektur pertahanan berbasis aturan dengan fokus komponen meliputi:

* **Analisis Struktur Log Mentah (Raw Field Mapping):** Memetakan parameter krusial dari Sysmon (`win.eventdata`) dan Zeek DNS logs (`zeek-alerts-4.x-*`) secara riil di Kibana Discover.
* **Rekayasa Aturan Deteksi (Custom Rules Engineering):** Membangun aturan deteksi berlapis (*child-rules*) berbasis kecocokan substring dan penanganan anomali struktur string pada skema format **Wazuh XML Rules** dan **KQL/Lucene Master Queries**.
* **Penyaringan Gangguan & Optimasi SIEM (Log Tuning):** Mengembangkan aturan pengecualian (*whitelist rules*) berkategori Level 0 untuk mereduksi faktor *alert fatigue* akibat aktivitas sistem yang normal.
* **Remediation & Pengerasan Sistem (System Hardening Blueprint):** Menyusun rekomendasi mitigasi konkret pada tingkat *endpoint* dan *network perimeter* guna memperkecil celah keamanan (*attack surface reduction*).

---

## 🏗️ Peta Telemetri & Log Mentah (Target Deteksi)

Berikut adalah field spesifik yang saya petakan dan validasi di lingkungan pengembangan untuk mendeteksi taktik *Living off the Land* (LotL) dan *DNS Tunneling*:

### 1. Host Logs (Sysmon & Windows PowerShell)
* **`win.eventdata.commandLine`**: Digunakan untuk memfilter eksekusi parameter utilitas administrative bawaan Windows (seperti kata kunci `schtasks`).
* **`win.eventdata.originalFileName`**: Deteksi tangguh untuk menangkap eksekusi `schtasks.exe` meskipun penyerang mengubah nama file binernya (*masquerading*).
* **`win.eventdata.path`**: Memantau jalur lokasi eksekusi skrip untuk mendeteksi berkas spesifik seperti `SharpHound.ps1`.
* **`win.eventdata.scriptBlockText`**: Target analisis konten log internal PowerShell (Event ID 4104) untuk mendeteksi pemanggilan fungsi spesifik (*string match*).

### 2. Network Logs (Zeek dns.log via Kibana)
* **`fields.log_source`**: Validasi awal untuk memastikan integritas asal log berasal dari subsistem sensor `zeek`.
* **`query.keyword`**: Target analisis string kueri subdomain berlapis (`*.tunnel.capstone8.com`) yang menandakan adanya *payload encoding* aktivitas DNS Tunneling.
* **`response_body_len`**: Indikator volume muatan data balasan dari DNS Server eksternal untuk mendeteksi jalur eksfiltrasi data massal.

---

## 🌐 Akses Monitoring Lab (SIEM Dashboard)

Untuk memantau visualisasi log, memvalidasi alert, dan menguji aturan deteksi secara langsung, dashboard Kibana diakses melalui perimeter jaringan virtual ZeroTier kelompok:

* **URL Akses Dashboard:** `http://<IP_VPN_NDA>:5601`

> ⚠️ **Catatan Pengembangan:** Variabel `<IP_VPN_NDA>` merujuk pada Managed IP dari laptop Network Analyst yang teralokasi pada dasbor ZeroTier Central kelompok. Pastikan agen ZeroTier lokal telah berstatus `Authorized` sebelum mengakses tautan di atas.

---

## 🛠️ Taksonomi Aturan Kustom (Wazuh Custom Rules Matrix)

Saya menerapkan standardisasi ID aturan kustom pada rentang **100001 - 100006** di dalam berkas konfigurasi `wazuh_rules.xml` untuk memisahkan kategori deteksi *host* dan *network* secara terstruktur:

| Rule ID | Komponen Target | Level | Mitre ATT&CK ID | Deskripsi Logika Deteksi |
| :--- | :--- | :--- | :--- | :--- |
| **100001** | **Host Log** (Sysmon) | Level 0 | None | *Parent Rule* penyaring awal aktivitas telemetri Sysmon berbasis Event ID terkait dari aturan bawaan. |
| **100002** | **Host Log** (Sysmon EID 1) | Level 8 | T1053.005 | Mendeteksi eksekusi Scheduled Task berdasarkan kecocokan biner asli `originalFileName: schtasks.exe`. |
| **100003** | **Host Log** (Sysmon EID 1) | Level 8 | T1087, T1053.005 | Mengantisipasi teknik *masquerading* dengan mendeteksi argumen CLI yang mengandung kata kunci teks `schtasks`. |
| **100004** | **Host Log** (PowerShell) | Level 12 | T1059.001, T1087.002 | Mendeteksi indikasi awal enumerasi Active Directory melalui deteksi nama file skrip `SharpHound.ps1` pada *script path*. |
| **100005** | **Host Log** (PowerShell) | Level 12 | T1059.001, T1027, T1087.002 | Mendeteksi eksekusi fungsi internal SharpHound di dalam isi konten skrip (*ScriptBlock Text*) untuk mencegah bypass penamaan berkas. |
| **100006** | **Network Log** (Zeek DNS) | Level 12 | T1071.004 | Mendeteksi anomali volume payload respons DNS, teks mencurigakan, dan pola subdomain terenkode (`*.tunnel.capstone8.com`). |

---

## 📁 Struktur Repositori (Detection Engineer Workspace)

```text
├── rules/
│   ├── kibana_zeek_alerts.txt  # Dokumentasi visualisasi & query alert subsistem jaringan Zeek
│   ├── query_kibana.txt        # Kumpulan kueri Master Hunting & Analisis Log di Kibana Discover
│   ├── sigma_rules.yml         # Playbook deteksi portabel berbasis format standarisasi Sigma
│   └── wazuh_rules.xml         # Berkas produksi aturan kustom XML lokal (ID: 100001-100006)
└── README.md                   # Dokumentasi utama proyek dan taksonomi lab