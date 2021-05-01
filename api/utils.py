import os
import requests


class CurrencyUtils:
    @staticmethod
    def iscurrency_valid(currency):
        url = f"https://v6.exchangerate-api.com/v6/{os.environ['API_KEY']}/codes"
        try:
            res = requests.get(url)
            codes = res.json()["supported_codes"]
            valid_code = False
            for code in codes:
                if code[0].lower() == currency.lower():
                    valid_code = True
                    break
            return valid_code
        except Exception:
            return False

    @staticmethod
    def convert_currency(_from, _to, amount):
        url = f"https://v6.exchangerate-api.com/v6/{os.environ['API_KEY']}/pair/{_from.upper()}/{_to.upper()}/{amount}"
        try:
            res = requests.get(url)
            value = float(res.json()["conversion_result"])
            return value
        except Exception:
            return False
