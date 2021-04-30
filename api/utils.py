import os
import requests


def iscurrency_valid(currency):
    url = f"http://data.fixer.io/api/latest?access_key={os.environ['FIXER_API_KEY']}"
    try :
        res = requests.get(url)
        rates = res.json()["rates"]
        return currency.upper() in rates.keys()
    except Exception:
        return False
