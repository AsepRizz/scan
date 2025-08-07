import re
import requests
from urllib.parse import parse_qs, urlencode

def parse_raw_request(raw_request):
    lines = raw_request.strip().split('\n')
    headers = {}
    body = ""
    body_started = False
    
    for line in lines:
        if not line.strip():
            body_started = True
            continue
            
        if not body_started:
            if ':' in line:
                key, val = line.split(':', 1)
                headers[key.strip()] = val.strip()
        else:
            body += line
    
    return headers, body

def main():
    # Input dari pengguna
    url = input("Masukkan URL target: ").strip()
    raw_request = input("Tempelkan raw request (dari Burp Suite):\n")
    
    # Parsing header dan body
    headers, body = parse_raw_request(raw_request)
    
    # Parsing parameter body
    params = parse_qs(body, keep_blank_values=True)
    params = {k: v[0] for k, v in params.items()}  # Ambil nilai pertama
    
    # Filter parameter yang tidak relevan
    irrelevant_params = ['submit', 'csrf', 'token', 'action', 'btn']
    relevant_params = [
        p for p in params.keys() 
        if not any(irr in p.lower() for irr in irrelevant_params)
    ]
    
    if not relevant_params:
        print("\nTidak ditemukan parameter yang relevan untuk diuji!")
        return
    
    # Tampilkan parameter yang bisa diubah
    print("\nParameter yang dapat diuji:")
    for i, param in enumerate(relevant_params, 1):
        print(f"{i}. {param} = {params[param]}")
    
    # Pilih parameter
    try:
        choice = int(input("\nPilih parameter (nomor): "))
        param_name = relevant_params[choice - 1]
    except (ValueError, IndexError):
        print("Pilihan tidak valid!")
        return
    
    # Input nilai
    start_val = input(f"\nMasukkan nilai awal [{param_name}]: ").strip() or params[param_name]
    end_val = input(f"Masukkan nilai akhir [{param_name}] (kosong=single test): ").strip()
    
    # Deteksi perubahan
    keyword = input("\nKeyword deteksi keberhasilan (contoh: 'Nilai Kelulusan'): ").strip()
    
    # Kirim request baseline
    print("\n[+] Mengirim request baseline...")
    baseline = requests.post(url, headers=headers, data=params)
    print(f"Status: {baseline.status_code}, Ukuran: {len(baseline.text)} bytes")
    
    # Konfigurasi pengujian
    test_values = [start_val]
    if end_val:
        try:
            step = 1 if float(end_val) >= float(start_val) else -1
            test_values = list(range(int(start_val), int(end_val) + step, step))
        except ValueError:
            test_values = [start_val, end_val]
    
    # Mulai pengujian
    print("\n[+] Memulai pengujian IDOR...")
    for val in test_values:
        # Modifikasi parameter
        modified_params = params.copy()
        modified_params[param_name] = val
        
        # Kirim request
        res = requests.post(url, headers=headers, data=modified_params)
        
        # Analisis perbedaan
        status_diff = " (STATUS BERBEDA!)" if res.status_code != baseline.status_code else ""
        size_diff = abs(len(res.text) - len(baseline.text))
        
        keyword_found = ""
        if keyword:
            keyword_found = " (KEYWORD DITEMUKAN)" if keyword in res.text else ""
        
        # Tampilkan hasil
        print(f"\nParameter: {param_name}={val}")
        print(f"Status: {res.status_code}{status_diff}")
        print(f"Ukuran: {len(res.text)} bytes (Δ: {size_diff})")
        
        if keyword:
            print(f"Keyword: {keyword_found}")
        
        # Deteksi perubahan signifikan
        if status_diff or (size_diff > 100) or keyword_found:
            print(">>> PERUBAHAN SIGNIFIKAN TERDETEKSI! <<<")

if __name__ == "__main__":
    main()