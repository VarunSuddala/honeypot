#!/usr/bin/env python3
"""
GeoIP Database Updater
Downloads and updates the GeoIP database for IP geolocation
"""

import os
import sys
import requests
import tarfile
import shutil
from datetime import datetime

# MaxMind GeoLite2 database information
# Note: You need to register for a free MaxMind account and get a license key
# https://dev.maxmind.com/geoip/geoip2/geolite2/
GEOIP_URL = "https://download.maxmind.com/app/geoip_download"
GEOIP_DB_NAME = "GeoLite2-City"
LICENSE_KEY = "YOUR_LICENSE_KEY"  # Replace with your MaxMind license key

def download_geoip_database():
    """Download the latest GeoIP database"""
    if not LICENSE_KEY or LICENSE_KEY == "YOUR_LICENSE_KEY":
        print("Error: You need to set your MaxMind license key in the script.")
        print("Register for a free account at https://www.maxmind.com/en/geolite2/signup")
        print("Then replace YOUR_LICENSE_KEY with your actual license key.")
        return False
        
    print(f"Downloading {GEOIP_DB_NAME} database...")
    
    # Create a temporary directory
    temp_dir = "temp_geoip"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    # Construct the download URL
    date_str = datetime.now().strftime("%Y%m%d")
    download_url = f"{GEOIP_URL}?edition_id={GEOIP_DB_NAME}&license_key={LICENSE_KEY}&suffix=tar.gz"
    
    try:
        # Download the database
        response = requests.get(download_url, stream=True)
        if response.status_code != 200:
            print(f"Error downloading database: HTTP {response.status_code}")
            print(response.text)
            return False
            
        # Save the downloaded file
        tar_file = os.path.join(temp_dir, f"{GEOIP_DB_NAME}.tar.gz")
        with open(tar_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
        # Extract the tar.gz file
        with tarfile.open(tar_file, 'r:gz') as tar:
            tar.extractall(path=temp_dir)
            
        # Find the .mmdb file in the extracted directory
        mmdb_file = None
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.mmdb'):
                    mmdb_file = os.path.join(root, file)
                    break
            if mmdb_file:
                break
                
        if not mmdb_file:
            print("Error: Could not find .mmdb file in the downloaded package.")
            return False
            
        # Copy the .mmdb file to the current directory
        shutil.copy(mmdb_file, f"{GEOIP_DB_NAME}.mmdb")
        print(f"Successfully downloaded and extracted {GEOIP_DB_NAME}.mmdb")
        
        # Clean up
        shutil.rmtree(temp_dir)
        return True
        
    except Exception as e:
        print(f"Error downloading or extracting database: {e}")
        return False

def check_database():
    """Check if the GeoIP database exists and is up to date"""
    db_file = f"{GEOIP_DB_NAME}.mmdb"
    
    if not os.path.exists(db_file):
        print(f"GeoIP database not found: {db_file}")
        return False
        
    # Check if the database is older than 30 days
    file_time = os.path.getmtime(db_file)
    file_date = datetime.fromtimestamp(file_time)
    days_old = (datetime.now() - file_date).days
    
    if days_old > 30:
        print(f"GeoIP database is {days_old} days old. Consider updating.")
        return False
        
    print(f"GeoIP database is {days_old} days old and valid.")
    return True

def main():
    """Main function"""
    print("GeoIP Database Updater")
    print("======================")
    
    if check_database():
        if len(sys.argv) > 1 and sys.argv[1] == "--force":
            print("Forcing database update...")
        else:
            print("Database is up to date. Use --force to update anyway.")
            return
            
    download_geoip_database()

if __name__ == "__main__":
    main()