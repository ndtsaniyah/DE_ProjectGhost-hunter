# Detection Engineer for Project Ghost-Hunter


# 🛡️ Ghost-Hunter: Detection Engineering & Defense Automation Lab
Repositori ini mendokumentasikan seluruh artefak teknis, logika deteksi, dan skrip otomatisasi mitigasi yang saya kembangkan sebagai **Detection Engineer** dalam proyek *Ghost-Hunter*. Fokus utama dari peran saya adalah mengubah telemetri mentah (log host & jaringan) menjadi aturan deteksi proaktif (*custom rules*) serta mengotomatisasikan triase insiden menggunakan Python.

---

## 🎯 Fokus Peran & Komponen Utama

Dalam proyek ini, saya bertanggung jawab penuh atas arsitektur pertahanan berbasis aturan dengan fokus utama:
1. **Analisis Struktur Log Mentah (Raw Field Mapping):** Memetakan parameter krusial dari Sysmon (`win.eventdata`) dan Zeek DNS logs (`zeek-alerts-4.x-*`) secara riil di Kibana Discover.
2. **Rekayasa Aturan Deteksi (Custom Rules Engineering):** Membangun aturan deteksi berlapis (*child-rules*) berbasis kecocokan substring dan penanganan anomali struktur string pada skema format **Wazuh XML Rules** dan **KQL/Lucene Master Queries**.
3. **Penyaringan Gangguan & Optimasi SIEM (Log Tuning):** Mengembangkan aturan pengecualian (*whitelist rules*) berkategori Level 0 untuk mereduksi faktor *alert fatigue* akibat aktivitas sistem yang normal.
4. **Remediation & Pengerasan Sistem (System Hardening Blueprint):** Menyusun rekomendasi mitigasi konkret pada tingkat *endpoint* dan *network perimeter* guna memperkecil celah keamanan (*attack surface reduction*).

---

## 🏗️ Peta Telemetri & Log Mentah (Target Deteksi)

Berikut adalah field spesifik yang saya petakan dan validasi di lingkungan pengembangan untuk mendeteksi taktik *Living off the Land* (LotL) dan *DNS Tunneling*:

### 1. Host Logs (Sysmon Event ID 1 & Event ID 11)
* **`win.eventdata.commandLine`**: Digunakan untuk memfilter eksekusi parameter utilitas administrative bawaan Windows (seperti kata kunci `schtasks` atau parameter penyamaran skrip `-encodedcommand`).
* **`win.eventdata.originalFileName`**: Deteksi tangguh untuk menangkap eksekusi `schtasks.exe` meskipun penyerang mengubah nama file binernya (*masquerading*).
* **`win.eventdata.targetFilename`**: Memantau pembuatan file baru; digunakan untuk mendeteksi sekaligus mengecualikan log uji coba kebijakan skrip (`__PSScriptPolicyTest`).

### 2. Network Logs (Zeek dns.log via Kibana)
* **`fields.log_source`**: Validasi awal untuk memastikan integritas asal log berasal dari subsistem sensor `zeek`.
* **`query.keyword`**: Target analisis string kueri subdomain berlapis (`*.*.*.*.tunnel.capstone8.com*`) yang menandakan adanya *payload encoding* dari utilitas `dnscat2`.
* **`response_body_len`**: Indikator volume muatan data balasan dari DNS Server eksternal untuk mendeteksi jalur eksfiltrasi data massal.

---

## 🌐 Akses Monitoring Lab (SIEM Dashboard)

Untuk memantau visualisasi log, memvalidasi alert, dan menguji aturan deteksi secara langsung, dashboard Kibana diakses melalui perimeter jaringan virtual ZeroTier kelompok:

* **URL Akses Dashboard:** `http://<IP_VPN_NDA>:5601`

> ⚠️ **Catatan Pengembangan:** Variabel `<IP_VPN_NDA>` merujuk pada Managed IP dari laptop Network Analyst yang teralokasi pada dasbor ZeroTier Central kelompok. Pastikan agen ZeroTier lokal telah berstatus `Authorized` sebelum mengakses tautan di atas.

---

## 🛠️ Taksonomi Aturan Kustom (Wazuh Custom Rules Matrix)

Saya menerapkan standardisasi ID aturan kustom pada rentang **100060 - 100070** di dalam file konfigurasi lokal manajer `wazuh_rules.xml` untuk memisahkan kategori deteksi secara terstruktur:

| Rule ID | Komponen Target | Level | Mitre ATT&CK ID | Deskripsi Logika Deteksi |
| :--- | :--- | :--- | :--- | :--- |
| **100060** | **Host Log** (Sysmon EID 1) | Level 0 | None | *Parent Rule* penyaring awal; membatasi ruang lingkup analisis pembuatan proses hanya pada **Agent 003**. |
| **100061** | **Host Log** (Sysmon EID 1) | Level 8 (Medium) | T1053.005 | Mendeteksi eksekusi Scheduled Task berdasarkan kecocokan biner asli `originalFileName: schtasks.exe`. |
| **100062** | **Host Log** (Sysmon EID 1) | Level 8 (Medium) | T1053.005 | Mengantisipasi teknik *masquerading* jika perintah CLI mengandung argumen teks `schtasks`. |
| **100063** | **Host Log** (Sysmon EID 1) | Level 12 (High) | T1059.001 | Mendeteksi taktik *Execution* via PowerShell Obfuscation menggunakan parameter `EncodedCommand`. |
| **100070** | **Tuning Rule** (Sysmon EID 11) | Level 0 (Silent) | None | *Tuning False Positive* untuk mengabaikan dan membungkam log pembuatan berkas normal `__PSScriptPolicyTest`. |
| **100071** | **Tuning Rule** (Sysmon EID 11) | Level 0 (Silent) | None | *Tuning False Positive* untuk mengabaikan pembuatan berkas aman di dalam direktori resmi `Chocolatey`. |

---

---

## 📁 Struktur Repositori (Detection Engineer Workspace)

├── .vscode/                  # Konfigurasi workspace lokal VS Code
├── rules/
│   ├── local_rules.xml       # File produksi aturan kustom & tuning Wazuh (ID: 00060-100070)
│   ├── kibana_kql_master.txt # Kumpulan kueri Master Hunting & Automated Alerting KQL/Lucene Zeek
│   └── sigma_rules.yml       # Draf aturan portabel berbasis format Sigma (Playbook Blueprint)
└── docs/
    ├── raw_fields_mapping.md # Dokumentasi hasil pemetaan field Sysmon & Zeek di Kibana
    └── remediation_guide.md  # Dokumen rekomendasi taktis pengerasan sistem (Mitigasi)
