import requests
import sys
import json

def get_rate(token):
    url = "https://api.github.com/rate_limit"
    headers = {
        "Authorization": f"token {token}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        rate_limit_info = response.json()
        print(token,rate_limit_info['rate']['limit'])
    else:
        print(token,response.text)

if __name__=="__main__":
    with open(sys.argv[1]) as f:
        content = f.read().split("\n")
    for line in content:
        if line.strip()=="":
            continue
        token = line.split(":")[1]
        get_rate(token)
