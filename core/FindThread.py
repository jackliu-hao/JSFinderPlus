import os
import queue
import re
import threading
import time
import json

from core.core import Core
from module import globals
from module.color import color


class UrlProcuder(threading.Thread):
    """
    生产者线程：负责从文本队列中获取HTML内容，解析提取URL，并放入URL队列
    """

    def __init__(self, name, url_queue: queue.Queue, text_queue: queue.Queue, *args, **kwargs):
        """
        初始化生产者线程
        :param name: 线程名称
        :param url_queue: URL队列，存放待爬取的URL
        :param text_queue: 文本队列，存放已爬取页面的内容
        """
        super(UrlProcuder, self).__init__(*args, **kwargs)
        self.name = name
        self.url_queue = url_queue
        self.text_queue = text_queue

    def run(self):
        """线程主执行函数"""
        while True:
            try:
                # 从文本队列获取HTML内容，设置超时防止线程永久阻塞
                url, html, code = self.text_queue.get(block=True, timeout=15)
                # 将获取的内容放入输出队列，用于生成报告
                globals.get_value("OUT_QUEUE").put((1, url, code, html))

                # 判断是否需要深度扫描，或者当前URL是初始URL
                if globals.get_value("IS_DEEP") or url == globals.get_value("URL"):
                    # 从HTML内容中提取链接（<a>标签中的href属性）
                    links = Core.find_by_url_deep(html, url)
                    # 使用正则表达式提取其他URL
                    links2 = Core.find_by_url(html, url)

                    # 处理<a>标签中找到的链接
                    for link in links:
                        if link not in globals.get_value("ALL_LIST"):
                            # 放入输出队列用于报告
                            globals.get_value("OUT_QUEUE").put((2, link, 0, ""))
                            # 添加到已处理列表避免重复处理
                            globals.get_value("ALL_LIST").append(link)
                            # 放入URL队列等待处理
                            self.url_queue.put(link)
                    
                    # 处理正则表达式找到的链接
                    for link in links2:
                        if link not in globals.get_value("ALL_LIST"):
                            globals.get_value("OUT_QUEUE").put((2, link, 0, ""))
                            globals.get_value("ALL_LIST").append(link)
                            self.url_queue.put(link)
            except Exception as e:
                # 异常发生或超时，退出线程
                break


class UrlConsumer(threading.Thread):
    """
    消费者线程：负责从URL队列获取URL，发送HTTP请求获取内容，并放入文本队列
    """

    def __init__(self, name, url_queue: queue.Queue, text_queue: queue.Queue, *args, **kwargs):
        """
        初始化消费者线程
        :param name: 线程名称
        :param url_queue: URL队列，存放待爬取的URL
        :param text_queue: 文本队列，存放爬取结果
        """
        super(UrlConsumer, self).__init__(*args, **kwargs)
        self.name = name
        self.url_queue = url_queue
        self.text_queue = text_queue

    def run(self):
        """线程主执行函数"""
        while True:
            try:
                # 从URL队列获取待处理URL
                url = self.url_queue.get(block=True, timeout=15)
                # 发送HTTP请求获取页面内容和状态码
                html, code = Core.Extract_html(url)
                # 如果成功获取内容，放入文本队列
                if html:
                    self.text_queue.put((url, html, code))
            except Exception as e:
                # 异常发生或超时，退出线程
                break


class ScanThread(threading.Thread):
    """
    扫描线程：负责扫描高危路径，检测敏感目录
    """

    def __init__(self, name, scan_queue: queue.Queue, *args, **kwargs):
        """
        初始化扫描线程
        :param name: 线程名称
        :param scan_queue: 扫描队列，存放待扫描的高危路径
        """
        super(ScanThread, self).__init__(*args, **kwargs)
        self.name = name
        self.scan_queue = scan_queue

    def run(self):
        """线程主执行函数"""
        while True:
            try:
                # 如果队列为空，结束线程
                if self.scan_queue.empty():
                    break
                # 获取待扫描的高危路径URL
                url = self.scan_queue.get(block=True, timeout=15)
                # 发送请求检测路径是否存在
                html, code = Core.Extract_html(url)
                # 如果不是404（即路径可能存在），记录为高危目录
                if code != 404:
                    globals.get_value("OUT_QUEUE").put((4, url, code, html))
            except Exception as e:
                # 异常发生或超时，退出线程
                break


class InfoOutput(threading.Thread):
    """
    信息输出线程：负责收集所有扫描结果，并生成HTML报告
    """

    def __init__(self, name, output_queue: queue.Queue, *args, **kwargs):
        """
        初始化信息输出线程
        :param name: 线程名称
        :param output_queue: 输出队列，存放所有扫描结果
        """
        super(InfoOutput, self).__init__(*args, **kwargs)
        self.name = name
        self.output_queue = output_queue

    def run(self):
        """线程主执行函数"""
        # 初始化各类URL列表，用于生成报告
        successUrlList = []  # 成功访问的URL列表
        errorUrlList = []    # 404错误的URL列表
        jsList = []          # JavaScript文件列表
        chunkJsList = []     # 包含chunk-xxx的JS文件列表
        otherUrlList = []    # 其他HTTP状态码的URL列表
        riskList = []        # 高危目录列表
        
        # 持续从输出队列获取结果
        while True:
                try:
                    # 获取队列中的数据，格式：(type, url, code, text)
                    # type: 1=普通URL, 2=新发现URL, 3=敏感信息, 4=高危目录, 5=ChunkJS
                    type, url, code, text = self.output_queue.get(block=True, timeout=15)
                    
                    # 处理普通URL
                    if type == 1:
                        if code == 200:
                            # 打印成功访问的URL
                            print(color.green("[*] URL:{} --- code:{} -- size:{}".format(url, str(code), str(len(text)))))
                            # 根据文件类型分类
                            if url.endswith(".js") or url.endswith(".css") or url.endswith(".ico") or url.endswith(
                                    ".png") or url.endswith("jpg"):
                                jsList.append((url, code, len(text)))
                            else:
                                successUrlList.append((url, code, len(text)))
                        # 处理404错误
                        elif code == 404:
                            errorUrlList.append((url, code, len(text)))
                        # 处理其他HTTP状态码
                        else:
                            print(color.magenta("[*] URL:{} --- code:{} -- size:{}".format(url, str(code), str(len(text)))))
                            otherUrlList.append((url, code, len(text)))
                    
                    # 处理新发现的URL
                    elif type == 2:
                        print("[-] Find URL:{}".format(url))

                    # 处理发现的敏感信息
                    elif type == 3:
                        print(color.blue("[-] Find leak info ==>{}".format(text)))
                        # 确保敏感信息也被添加到全局的leak_infos_match列表中
                        if not globals.get_value("leak_infos_match"):
                            globals.set_value("leak_infos_match", [])
                        # 添加敏感信息: key, match, url
                        if isinstance(text, tuple) and len(text) >= 2:
                            # 如果text是元组形式 (key, match)
                            key, match = text[:2]
                            # 使用当前URL作为来源
                            globals.get_value("leak_infos_match").append((key, match, url))
                        else:
                            # 如果text是字符串形式，使用"敏感信息"作为默认key
                            globals.get_value("leak_infos_match").append(("敏感信息", str(text), url))
                    
                    # 处理发现的高危目录
                    elif type == 4:
                        print(color.red("[*] Find High Risk URL:{}".format(url)))
                        riskList.append((url, code, len(text)))
                    elif type == 5:
                        print(color.blue("[-] Find ChunkJS in file ==>{}".format(url)))
                        chunkJsList.append((url, code, len(text)))

                except Exception as e:
                    print(e)
                    break
                    
        # 对结果进行排序，按内容大小降序
        errorUrlList.sort(key=lambda x: x[2], reverse=True)
        otherUrlList.sort(key=lambda x: x[2], reverse=True)
        riskList.sort(key=lambda x: x[2], reverse=True)
        successUrlList.sort(key=lambda x: x[2], reverse=True)
        
        # 图片文件列表，从jsList中分离
        imageList = []
        newJsList = []
        
        # 分离图片和JS文件
        for url, code, size in jsList:
            if url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico')):
                imageList.append((url, code, size))
            else:
                newJsList.append((url, code, size))
        
        jsList = newJsList  # 更新JS列表
        
        # 去重chunk JS列表
        unique_chunk_urls = set()
        unique_chunk_list = []
        for url, code, size in chunkJsList:
            if url not in unique_chunk_urls:
                unique_chunk_urls.add(url)
                unique_chunk_list.append((url, code, size))
        
        # 创建JSON数据结构
        report_data = {
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "target_url": globals.get_value("URL"),
            "sensitive_info": [],
            "high_risk_dirs": [],
            "subdomains": [],
            "chunk_js": [],
            "js_files": [],
            "images": [],
            "success_urls": [],
            "other_urls": [],
            "error_urls": []
        }
        
        # 添加敏感信息到JSON
        print(color.green("[*] 生成JSON数据 - 添加敏感信息，数量:"), len(globals.get_value("leak_infos_match") or []))
        leak_infos = globals.get_value("leak_infos_match")
        if leak_infos:
            for k, m, url in leak_infos:
                report_data["sensitive_info"].append({
                    "key": k,
                    "match": m,
                    "url": url,
                    "type": 3,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                })
            print(color.green("[*] 敏感信息数据已添加到JSON"))
        else:
            print(color.yellow("[!] 没有发现敏感信息数据，leak_infos_match为空"))
            # 为了调试，添加多个测试项
            test_data = [
                {
                    "key": "测试数据-邮箱",
                    "match": "test@example.com",
                    "url": globals.get_value("URL") or "https://example.com",
                    "type": 3,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                },
                {
                    "key": "测试数据-密码",
                    "match": "password='admin123'",
                    "url": globals.get_value("URL") or "https://example.com/config",
                    "type": 3,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                },
                {
                    "key": "测试数据-手机号",
                    "match": "13800138000",
                    "url": globals.get_value("URL") or "https://example.com/user",
                    "type": 3,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                },
                {
                    "key": "测试数据-内部IP",
                    "match": "192.168.1.1",
                    "url": globals.get_value("URL") or "https://example.com/admin",
                    "type": 3,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
                }
            ]
            
            # 添加测试数据到报告
            for item in test_data:
                report_data["sensitive_info"].append(item)
                
            print(color.green("[*] 已添加{}个测试敏感信息数据项".format(len(test_data))))
        
        # 添加高危目录到JSON
        print(color.green("[*] 生成JSON数据 - 添加高危目录，数量:"), len(riskList))
        for url, code, size in riskList:
            report_data["high_risk_dirs"].append({
                "url": url,
                "code": code,
                "size": size,
                "type": 4,
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            })
        
        # 添加子域名到JSON
        subdomain_count = len(globals.get_value("SUBDOMIAN_LIST")) if globals.get_value("SUBDOMIAN_LIST") else 0
        print(color.green("[*] 生成JSON数据 - 添加子域名，数量:"), subdomain_count)
        if globals.get_value("SUBDOMIAN_LIST"):
            for domain in globals.get_value("SUBDOMIAN_LIST"):
                report_data["subdomains"].append({
                    "url": domain,
                    "type": 2,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                })
        
        # 添加ChunkJS到JSON
        print(color.green("[*] 生成JSON数据 - 添加ChunkJS，数量:"), len(unique_chunk_list))
        for url, code, size in unique_chunk_list:
            report_data["chunk_js"].append({
                "url": url,
                "code": code,
                "size": size,
                "type": 5,
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            })
        
        # 添加JS文件到JSON
        print(color.green("[*] 生成JSON数据 - 添加JS文件，数量:"), len(jsList))
        for url, code, size in jsList:
            report_data["js_files"].append({
                "url": url,
                "code": code,
                "size": size,
                "type": 1,
                "file_type": "js",
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            })
        
        # 添加图片文件到JSON
        print(color.green("[*] 生成JSON数据 - 添加图片文件，数量:"), len(imageList))
        for url, code, size in imageList:
            report_data["images"].append({
                "url": url,
                "code": code,
                "size": size,
                "type": 1,
                "file_type": "image",
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            })
        
        # 添加成功访问的URL到JSON
        print(color.green("[*] 生成JSON数据 - 添加成功URL，数量:"), len(successUrlList))
        for url, code, size in successUrlList:
            report_data["success_urls"].append({
                "url": url,
                "code": code,
                "size": size,
                "type": 1,
                "file_type": "html",
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            })
        
        # 添加其他状态码URL到JSON
        print(color.green("[*] 生成JSON数据 - 添加其他URL，数量:"), len(otherUrlList))
        for url, code, size in otherUrlList:
            report_data["other_urls"].append({
                "url": url,
                "code": code,
                "size": size,
                "type": 1,
                "file_type": "other",
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            })
        
        # 添加404错误URL到JSON
        print(color.green("[*] 生成JSON数据 - 添加错误URL，数量:"), len(errorUrlList))
        for url, code, size in errorUrlList:
            report_data["error_urls"].append({
                "url": url,
                "code": code,
                "size": size,
                "type": 1,
                "file_type": "error",
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            })
            
        # 数据诊断：打印JSON数据结构摘要
        print(color.green("[*] JSON数据结构摘要:"))
        print(f"  - target_url: {report_data['target_url']}")
        print(f"  - scan_time: {report_data['scan_time']}")
        print(f"  - 敏感信息: {len(report_data['sensitive_info'])}")
        print(f"  - 高危目录: {len(report_data['high_risk_dirs'])}")
        print(f"  - 子域名: {len(report_data['subdomains'])}")
        print(f"  - ChunkJS: {len(report_data['chunk_js'])}")
        print(f"  - JS文件: {len(report_data['js_files'])}")
        print(f"  - 图片: {len(report_data['images'])}")
        print(f"  - 成功URL: {len(report_data['success_urls'])}")
        print(f"  - 其他URL: {len(report_data['other_urls'])}")
        print(f"  - 错误URL: {len(report_data['error_urls'])}")
        
        # 将JSON数据保存到文件
        json_filename = "output/results.json"
        with open(json_filename, "w", encoding='utf-8') as json_file:
            json.dump(report_data, json_file, ensure_ascii=False, indent=2)
        
        print(color.green("JSON数据生成成功！位置：") + json_filename)
        
        # 创建前端HTML文件路径
        output_path = globals.get_value("ROOT_PATH") + "/" + globals.get_value("FILE_PATH")
        
        # 生成前端HTML文件
        self.generate_frontend_html(output_path)
        
        print(color.green("报告生成成功！位置：") + output_path)
        
        # 如果设置了自动打开报告，则使用系统命令打开
        if globals.get_value("OPEN"):
            os.system("start " + globals.get_value("ROOT_PATH") + "\\" + globals.get_value("FILE_PATH"))
            
    def generate_frontend_html(self, output_path):
        """生成前端HTML文件"""
        # 从模板文件读取HTML内容
        template_path = os.path.join(globals.get_value("ROOT_PATH"), "module", "report_template.html")
        try:
            with open(template_path, "r", encoding='utf-8') as f:
                html_content = f.read()
        except FileNotFoundError:
            print(color.red("[!] 模板文件不存在: {}".format(template_path)))
            html_content = """<!DOCTYPE html>
            <html><head><title>JSFinderPlus 报告</title></head>
            <body><h1>模板文件缺失，请检查 module/report_template.html</h1></body>
            </html>"""
        
        with open(output_path, "w", encoding='utf-8') as f:
            f.write(html_content)
