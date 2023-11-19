from browsermobproxy import Server
from selenium import webdriver
import json

#create a browsermob server instance
server = Server("/Users/youssefqteishat/Downloads/drive-download-20231119T192455Z-001/bin/browsermob-proxy")
server.start()
proxy = server.create_proxy(params=dict(trustAllServers=True))