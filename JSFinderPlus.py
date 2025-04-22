#!/usr/bin/env python"
# coding: utf-8
# By Threezh1
# https://threezh1.github.io/
import os
import queue
import re
from urllib.parse import urlparse

import urllib3

from core.FindThread import UrlProcuder, UrlConsumer, InfoOutput, ScanThread
from core.core import Core
from module import globals
from module.argparse import arg
from module.banner import banner
from module.color import color
from module.proxy import proxy_set


def load_globals(args):
    header = {
        'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                  'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
        'User-agent': args.ua,
        'Cookie': args.cookie,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close'
    }
    globals.init()  # 初始化全局变量模块
    globals.set_value("HEADERS", header)
    globals.set_value("URL", args.url)
    globals.set_value("OPEN", args.open)
    globals.set_value("ROOT_PATH", os.path.abspath('.'))
    if args.root:
        if args.root.endswith("/"):
            globals.set_value("SITE_ROOT", args.root[:-1])
        globals.set_value("SITE_ROOT", args.root)

    globals.set_value("IS_DEEP", args.deep)
    globals.set_value("ALL_LIST", [])
    globals.set_value("SUBDOMIAN_LIST", [])
    globals.set_value("leak_infos_match", [])

    if args.url:
        filename = urlparse(args.url).hostname
        if not os.path.exists("output"):
            os.makedirs("output")
        filename = re.sub(re.compile(r'[/\\:*?"<>|]'), "_", filename)
        globals.set_value("FILE_PATH", "output\\" + filename + ".html")


def read_urls_from_file(file_path):
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):  # 忽略空行和注释行
                    urls.append(url)
        return urls
    except Exception as e:
        print(color.red_error() + f"读取文件 {file_path} 出错: {str(e)}")
        exit(1)


def process_single_url(url, args, t_num):
    # 设置当前URL的输出文件路径
    filename = urlparse(url).hostname
    if not os.path.exists("output"):
        os.makedirs("output")
    filename = re.sub(re.compile(r'[/\\:*?"<>|]'), "_", filename)
    globals.set_value("FILE_PATH", "output\\" + filename + ".html")
    globals.set_value("URL", url)
    
    url_queue = queue.Queue(100000)      # 存储待处理的URL
    text_queue = queue.Queue(100000)     # 存储URL对应的HTML内容
    output_queue = queue.Queue(1000000)  # 存储最终处理结果
    globals.set_value("OUT_QUEUE", output_queue)
    globals.set_value("ALL_LIST", [])
    globals.set_value("SUBDOMIAN_LIST", [])
    globals.set_value("leak_infos_match", [])
    
    url_queue.put(url)
    globals.get_value("ALL_LIST").append(url)
    
    t_list = []
    
    # 先消费初始url，根据html在生产其他url
    for x in range(t_num):
        t = UrlConsumer(name='消费线程-%d' % x, url_queue=url_queue, text_queue=text_queue)
        t_list.append(t)
        t.start()
    
    for x in range(t_num):
        t = UrlProcuder(name='生产线程-%d' % x, url_queue=url_queue, text_queue=text_queue)
        t_list.append(t)
        t.start()
    
    scan_queue = queue.Queue(1000)
    # 扫描高危目录
    with open(globals.get_value("ROOT_PATH") + "/module/dict.txt", "r", encoding='utf-8') as f:
        line = f.readline()
        while line:
            scan_queue.put(Core.process_url(url, line.replace("\n", "")))
            line = f.readline()
    
    for x in range(5):
        t = ScanThread(name='扫描高危路径-%d' % x, scan_queue=scan_queue)
        t_list.append(t)
        t.start()
    
    # 信息输出线程
    t = InfoOutput(name='信息输出线程-%d' % 1, output_queue=output_queue)
    t_list.append(t)
    t.start()
    
    for t in t_list:
        t.join()
    
    print(color.green("[+]") + f" URL {url} 扫描完成，结果保存在: {globals.get_value('FILE_PATH')}")


if __name__ == "__main__":
    urllib3.disable_warnings()
    print(banner)
    args = arg()
    load_globals(args)  # 加载全局变量
    if args.socks:
        proxy_set(args.socks, "socks")  # proxy support socks5 http https
    elif args.http:
        proxy_set(args.http, "http")  # proxy support socks5 http https

    t_num = args.thread_num  # 线程数量
    
    if args.url:
        process_single_url(args.url, args, t_num)
    elif args.file:
        print(color.green("[+]") + f" 从文件 {args.file} 读取URL列表进行批量扫描")
        urls = read_urls_from_file(args.file)
        if not urls:
            print(color.red_error() + f"文件 {args.file} 中没有有效的URL")
            exit(0)
        
        print(color.green("[+]") + f" 共读取到 {len(urls)} 个URL")
        for i, url in enumerate(urls):
            print(color.green("[+]") + f" 开始扫描第 {i+1}/{len(urls)} 个URL: {url}")
            process_single_url(url, args, t_num)
    else:
        print(color.red_error() + "缺少必要参数，请使用 -u 指定URL或使用 -f 指定URL文件")
        exit(0)
