from threat_feed_aggregator.geoip_manager import get_country_code
import os

print(f"Current working directory: {os.getcwd()}")
ip = "8.8.8.8"
country = get_country_code(ip)
print(f"IP: {ip}, Country: {country}")

if country == "US":
    print("GeoIP Test PASSED")
else:
    print("GeoIP Test FAILED")
