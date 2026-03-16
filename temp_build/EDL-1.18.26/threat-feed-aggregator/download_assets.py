import os
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "threat_feed_aggregator", "static", "vendor")

files = [
    # CSS
    ("https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css", "css/bootstrap.min.css"),
    ("https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css", "css/fontawesome.min.css"),
    ("https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css", "css/sweetalert2.min.css"),
    ("https://cdn.jsdelivr.net/npm/jsvectormap/dist/css/jsvectormap.min.css", "css/jsvectormap.min.css"),
    
    # JS
    ("https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js", "js/bootstrap.bundle.min.js"),
    ("https://cdn.jsdelivr.net/npm/chart.js", "js/chart.js"),
    ("https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.all.min.js", "js/sweetalert2.all.min.js"),
    ("https://cdn.jsdelivr.net/npm/jsvectormap/dist/js/jsvectormap.min.js", "js/jsvectormap.min.js"),
    ("https://cdn.jsdelivr.net/npm/jsvectormap/dist/maps/world.js", "js/world.js"),
    
    # jQuery (Required for DataTables)
    ("https://code.jquery.com/jquery-3.7.1.min.js", "js/jquery.min.js"),

    # DataTables
    ("https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css", "css/dataTables.bootstrap5.min.css"),
    ("https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js", "js/jquery.dataTables.min.js"),
    ("https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js", "js/dataTables.bootstrap5.min.js"),

    # Webfonts (FontAwesome)
    ("https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-solid-900.woff2", "webfonts/fa-solid-900.woff2"),
    ("https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-brands-400.woff2", "webfonts/fa-brands-400.woff2"),
    ("https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-regular-400.woff2", "webfonts/fa-regular-400.woff2"),
]

def download_file(url, local_path):
    full_path = os.path.join(STATIC_DIR, local_path)
    print(f"Downloading {url} to {local_path}...")
    try:
        r = requests.get(url, stream=True)
        r.raise_for_status()
        with open(full_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        print("Success.")
    except Exception as e:
        print(f"Failed to download {url}: {e}")

if __name__ == "__main__":
    for url, path in files:
        download_file(url, path)
