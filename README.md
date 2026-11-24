# Implementasi Arsitektur Perimeter Security: FortiGate NGFW, DMZ Zone, & MikroTik RouterOS

Dokumentasi praktik laboratorium keamanan jaringan (*Network Security Engineering*) menggunakan **PNETLab**, **FortiGate Next-Generation Firewall (NGFW)**, **MikroTik RouterOS (Winbox)**, dan **Ubuntu Server**. Proyek ini menyimulasikan arsitektur jaringan perusahaan tiga zona (**LAN**, **DMZ**, dan **WAN**) dengan kontrol akses berbasis *Zero-Trust / Implicit Deny* serta publikasi layanan web internal ke jaringan publik menggunakan **Virtual IP (DNAT / Port Forwarding)**.

---

## 1. Arsitektur & Topologi Jaringan

![Topologi Jaringan](<assets/Topologi-jaringan.png>)

### Gambaran Umum Infrastruktur
* **Perimeter Firewall (`FortiGate NGFW`):** Bertindak sebagai gerbang keamanan utama antara jaringan eksternal (`port3` / WAN) dan jaringan internal (`port2` / LAN & DMZ). Mengelola translasi alamat keluar (**SNAT / Masquerade**) serta penerjemahan alamat masuk (**DNAT / Virtual IP**) untuk layanan publik di DMZ.
* **Core Router (`Router Utama` — MikroTik):** Berfungsi sebagai *Internal Gateway* yang melakukan perutean antar-segmen lokal (**LAN `192.168.10.0/24`** dan **DMZ `172.16.10.0/24`**) serta menyediakan layanan **DHCP Server** bagi klien internal.
* **Server DMZ (`Ubuntu Server`):** Berada di segmen terisolasi (*Demilitarized Zone*) dan menjalankan layanan **HTTP Web Server (Port 80)** yang dapat diakses dari jaringan publik secara terkendali tanpa mengekspos segmen LAN internal.
* **Simulasi Internet (`Router ISP` — MikroTik):** Menyimulasikan jaringan publik (`100.100.100.0/24`), target konektivitas internet (`8.8.8.8`), serta bertindak sebagai klien eksternal untuk menguji akses publik ke Server DMZ.
* **Out-of-Band Management (`Cloud0` / VMnet8):** Jalur terpisah (`192.168.200.0/24`) untuk mengakses Web GUI FortiGate dan Winbox MikroTik secara stabil tanpa memengaruhi tabel *routing* utama.

---

## 2. Tabel Pengalamatan IP (IP Addressing Plan)

| Perangkat | Interface | Zona / Peran | IP Address | Keterangan |
| :--- | :--- | :--- | :--- | :--- |
| **Router ISP** | `ether2` | WAN / Publik | `100.100.100.1/24` | Simulasi Gateway ISP |
| **Router ISP** | `loopback` | Target Internet | `8.8.8.8/32` | Simulasi Public DNS / Internet |
| **FortiGate NGFW** | `port1` | Management | `192.168.200.x/24` | Akses Web GUI (`HTTPS`) |
| **FortiGate NGFW** | `port3` | Zone: **WAN** | `100.100.100.2/24` | Uplink ke `Router ISP` + Virtual IP (`100.100.100.2:80`) |
| **FortiGate NGFW** | `port2` | Zone: **INTERNAL-LAN-DMZ** | `10.10.10.1/30` | Transit Point-to-Point ke `Router Utama` |
| **Router Utama** | `ether1` | Uplink Transit | `10.10.10.2/30` | Default Route ke FortiGate (`10.10.10.1`) |
| **Router Utama** | `ether2` | Zone: **LAN** | `192.168.10.1/24` | Gateway & DHCP Server Klien Internal |
| **Router Utama** | `ether3` | Zone: **DMZ** | `172.16.10.1/24` | Gateway Segmen Server DMZ |
| **Klien Internal (`VPC`)** | `eth0` | End-User LAN | `192.168.10.x/24` | Dinamis via DHCP (`Router Utama`) |
| **Server DMZ (`Ubuntu`)** | `eth1` | Web Server DMZ | `172.16.10.10/24` | Statis, HTTP Service aktif di Port `80` |

---

## 3. Tahapan Konfigurasi Inti

### A. Routing Transit & Segmentasi Jaringan (`Router Utama` & `FortiGate`)
1. **Perutean Dua Arah (*Bidirectional Static Routing*):**
   * **`Router Utama`:** Mengarahkan seluruh trafik keluar (`0.0.0.0/0`) menuju interface internal FortiGate (`10.10.10.1`).
   * **`FortiGate NGFW`:** Menambahkan *Static Route* balik untuk subnet **LAN (`192.168.10.0/24`)** dan **DMZ (`172.16.10.0/24`)** melalui gateway `10.10.10.2` (`port2`) agar paket balasan dari internet dan klien eksternal dapat mencapai host tujuan.
2. **Konfigurasi Ubuntu Server DMZ:**
   * Menetapkan IP statis `172.16.10.10/24` dengan gateway `172.16.10.1` pada interface lab (`eth1`) dan menjalankan layanan HTTP server pada port `80`.

### B. Virtual IP / Port Forwarding (`VIP-Web-DMZ`)
Untuk mengizinkan pengguna eksternal mengakses layanan web di Server DMZ tanpa mengetahui topologi internal, dikonfigurasi objek **Virtual IP (DNAT)** pada FortiGate (**Policy & Objects $\rightarrow$ Virtual IPs**):
* **Name:** `VIP-Web-DMZ`
* **Interface:** `port3` (WAN)
* **External IP Address:** `100.100.100.2`
* **Mapped IPv4 Address:** `172.16.10.10`
* **Port Forwarding:** `Enabled` (**Protocol:** `TCP`, **External Port:** `80` $\rightarrow$ **Map to Port:** `80`)

![Virtual IP FortiGate](<assets/Virtual-IP-FortiGate.png>)

### C. Kebijakan Keamanan Firewall (`Firewall Policy`)
FortiGate menerapkan prinsip ***Implicit Deny*** secara bawaan, sehingga seluruh lalu lintas lintas-zona harus diizinkan secara eksplisit:

| ID | Nama Policy | Incoming Interface | Outgoing Interface | Source | Destination | Service | Action | NAT |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `LAN-to-Internet` | `port2` (`INTERNAL-LAN-DMZ`) | `port3` (`WAN`) | `LAN-Subnet` (`192.168.10.0/24`), `DMZ-Subnet` (`172.16.10.0/24`) | `all` | `ALL` | **ACCEPT** | **Enabled** (SNAT) |
| **3** | `WAN-to-DMZ-Web` | `port3` (`WAN`) | `port2` (`INTERNAL-LAN-DMZ`) | `all` | `VIP-Web-DMZ` | `HTTP` | **ACCEPT** | **Disabled** (Ditangani VIP) |

![Firewall Policy FortiGate](<assets/Firewall-Policy-FortiGate.png>)

---

## 4. Matriks Hasil Pengujian & Verifikasi End-to-End

Pengujian dilakukan secara bertahap dari sisi internal (`VPC`), segmen DMZ (`Ubuntu Server`), hingga sisi eksternal (`Router ISP`):

| Skenario Pengujian | Perintah Uji | Hasil | Analisis Teknis |
| :--- | :--- | :--- | :--- |
| **1. Klien LAN $\rightarrow$ Internet** | `ping 8.8.8.8` (dari `VPC`) | **Berhasil (`Reply`)** | Klien menerima IP DHCP, dirutekan oleh `Router Utama`, dan ditranslasikan SNAT oleh FortiGate. |
| **2. Klien LAN $\rightarrow$ Server DMZ** | `ping 172.16.10.10` (dari `VPC`) | **Berhasil (`Reply`)** | Perutean lokal antar-interface (`ether2` $\leftrightarrow$ `ether3`) pada `Router Utama` berjalan normal. |
| **3. Server DMZ $\rightarrow$ Internet** | `ping -c 4 8.8.8.8` (dari `Ubuntu DMZ`) | **Berhasil (`Reply`)** | Paket keluar diizinkan setelah `DMZ-Subnet` ditambahkan ke policy `LAN-to-Internet`. |
| **4. Publik (WAN) $\rightarrow$ Web DMZ** | `/tool fetch url="http://100.100.100.2" mode=http output=user` (dari `Router ISP`) | **Berhasil (`status: finished`)** | Permintaan HTTP ke IP Publik `100.100.100.2:80` diterjemahkan oleh `VIP-Web-DMZ` ke `172.16.10.10:80` dan mengembalikan konten HTML dari Ubuntu Server. |

### Bukti Pengujian Akses Klien Internal (`VPC`) & Server DMZ (`Ubuntu`)
* Klien internal (`VPC`) berhasil memperoleh IP DHCP, menjangkau internet (`8.8.8.8`), dan terhubung ke Server DMZ (`172.16.10.10`).

![Testing Ping VPC](<assets/Testing-VPC.png>)

* Server DMZ (`Ubuntu Server`) memiliki konfigurasi IP statis `172.16.10.10/24`, layanan web port `80` aktif, dan berhasil melakukan *ping* ke `8.8.8.8`.

![Testing Ping Server DMZ](<assets/Testing-ServerDMZ.png>)

### Bukti Pengujian Akses Publik ke Server DMZ (Port Forwarding / VIP)
* Pengujian HTTP dari terminal `Router ISP` (sisi WAN) menuju IP Publik Virtual IP (`100.100.100.2`) berhasil menarik halaman web dari Ubuntu Server DMZ (`172.16.10.10`) dengan peningkatan *Hit Count* pada objek `VIP-Web-DMZ` dan policy `WAN-to-DMZ-Web`.

![Testing VIP Port Forwarding](<assets/Testing-VIP-DMZ.png>)

---

## 5. Catatan Troubleshooting Selama Praktikum

1. **Paket Balasan dari Internet Tidak Kembali ke Segmen LAN/DMZ:**
   * *Penyebab:* FortiGate hanya mengenali jaringan yang terhubung langsung (`10.10.10.0/30` dan `100.100.100.0/24`), sehingga paket balasan menuju `192.168.10.0/24` maupun `172.16.10.0/24` dibuang.
   * *Solusi:* Menambahkan *Static Route* pada FortiGate menuju kedua subnet tersebut dengan *next-hop* `10.10.10.2` (`Router Utama`).
2. **Server DMZ Gagal Mengakses `8.8.8.8` (*Implicit Deny*):**
   * *Penyebab:* Objek `DMZ-Subnet` (`172.16.10.0/24`) belum didaftarkan pada kolom *Source* di aturan `LAN-to-Internet`.
   * *Solusi:* Membuat objek alamat `DMZ-Subnet` dan menambahkannya ke dalam *Source* pada policy `LAN-to-Internet`.
3. **Error `failure: cannot open file: Is a directory` saat Pengujian HTTP di MikroTik:**
   * *Penyebab:* Perintah `/tool fetch url="http://100.100.100.2"` tanpa parameter nama file menyebabkan RouterOS mencoba menyimpan respons root URL (`/`) sebagai nama direktori.
   * *Solusi:* Menambahkan parameter `output=user` (atau `dst-path=dmz.html`) sehingga isi halaman web dari Ubuntu Server DMZ berhasil ditampilkan langsung di terminal `Router ISP`.
