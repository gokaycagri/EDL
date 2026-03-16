import re

DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")

domains = [
    "onlndi-sileye-gt.cfd",
    "anlayamazsnfirstlr.duckdns.org",
    "iadesistemi.otzo.com",
    "101-de-bugune-ozel-indirimler-tr.mooo.com",
    "onaltocakkampanya.blogspot.com",
    "beautynow.my"
]

for d in domains:
    match = DOMAIN_PATTERN.match(d)
    print(f"{d}: {'MATCH' if match else 'NO MATCH'}")
