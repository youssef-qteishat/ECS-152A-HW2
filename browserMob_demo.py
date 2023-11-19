# Week 6 discussion:
# 00:00 to 18:00 -> BrowserMob Proxy Setup
# 18:00 to end   -> Byte manipulation and Socket Programming

from browsermobproxy import Server
from selenium import webdriver
import json

#create a browsermob server instance
server = Server("/Users/youssefqteishat/Downloads/drive-download-20231119T192455Z-001/bin/browsermob-proxy")
server.start()
proxy = server.create_proxy(params=dict(trustAllServers=True))

#create a new chromedriver instance
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--proxy-server={}".format(proxy.proxy))
chrome_options.add_argument('--ignore-cretifcate-errors')
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-gpu")
driver = webdriver.Chrome(options=chrome_options)

#create new har file inside proxy and do crawling
proxy.new_har("myhar")
driver.get("http://www.cnn.com")

#write har file to external file
#then you can run two scripts, one for crawling and then one for processing
#later on a script can read this file via json and extract whatever info it needs
with open('myhar.har', 'w') as f:
    f.write(json.dumps(proxy.har))

#stop server and exit
server.drop()
driver.quit()