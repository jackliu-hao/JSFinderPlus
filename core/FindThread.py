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
            if url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp' , '.pdf' )):
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
                # {
                #     "key": "测试数据-内部IP",
                #     "match": "192.168.1.1",
                #     "url": globals.get_value("URL") or "https://example.com/admin",
                #     "type": 3,
                #     "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
                # }
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
        
        # 将JSON数据保存或合并到文件
        json_filename = "output/results.json"
        merged_data = self.merge_with_existing_json(json_filename, report_data)
        
        with open(json_filename, "w", encoding='utf-8') as json_file:
            json.dump(merged_data, json_file, ensure_ascii=False, indent=2)
        
        print(color.green("JSON数据生成成功！位置：") + json_filename)
        
        # 创建前端HTML文件路径 - 固定为report.html
        output_path = os.path.join(globals.get_value("ROOT_PATH"), "output", "report.html")
        
        # 生成前端HTML文件（不再使用模板，直接内联所有HTML）
        # self.generate_frontend_html(output_path)
        
        print(color.green("报告生成成功！位置：") + output_path)
        
        # 如果设置了自动打开报告，则使用系统命令打开
        if globals.get_value("OPEN"):
            os.system("start " + output_path)
            
    def merge_with_existing_json(self, json_filename, new_data):
        """合并新的扫描数据和已有的JSON数据"""
        try:
            # 如果文件已存在，尝试读取并合并数据
            if os.path.exists(json_filename):
                try:
                    with open(json_filename, "r", encoding='utf-8') as f:
                        existing_data = json.load(f)
                    
                    # 创建合并后的数据结构
                    merged_data = {
                        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                        "target_urls": [],
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
                    
                    # 如果已有数据是批量扫描格式
                    if "target_urls" in existing_data:
                        merged_data["target_urls"] = existing_data["target_urls"]
                        
                        # 检查当前URL是否已在列表中
                        if new_data["target_url"] not in merged_data["target_urls"]:
                            merged_data["target_urls"].append(new_data["target_url"])
                    else:
                        # 如果已有数据是单URL格式，将其转换为批量格式
                        if "target_url" in existing_data and existing_data["target_url"]:
                            merged_data["target_urls"].append(existing_data["target_url"])
                        # 添加新的URL
                        if new_data["target_url"] not in merged_data["target_urls"]:
                            merged_data["target_urls"].append(new_data["target_url"])
                    
                    # 合并各类数据，避免重复
                    for key in ["sensitive_info", "high_risk_dirs", "subdomains", "chunk_js", 
                                "js_files", "images", "success_urls", "other_urls", "error_urls"]:
                        # 已有数据
                        if key in existing_data:
                            merged_data[key].extend(existing_data[key])
                        
                        # 新数据
                        if key in new_data:
                            # 对于某些数据类型，我们需要检查URL是否重复
                            if key in ["chunk_js", "js_files", "images", "success_urls", "other_urls", "error_urls"]:
                                existing_urls = set(item["url"] for item in merged_data[key])
                                for item in new_data[key]:
                                    if item["url"] not in existing_urls:
                                        merged_data[key].append(item)
                                        existing_urls.add(item["url"])
                            elif key == "subdomains":
                                existing_domains = set(item["url"] for item in merged_data[key])
                                for item in new_data[key]:
                                    if item["url"] not in existing_domains:
                                        merged_data[key].append(item)
                                        existing_domains.add(item["url"])
                            elif key == "sensitive_info":
                                # 对敏感信息，需要更复杂的去重逻辑
                                for item in new_data[key]:
                                    is_duplicate = False
                                    for existing_item in merged_data[key]:
                                        if (item["key"] == existing_item["key"] and 
                                            item["match"] == existing_item["match"] and
                                            item["url"] == existing_item["url"]):
                                            is_duplicate = True
                                            break
                                    if not is_duplicate:
                                        merged_data[key].append(item)
                            else:
                                # 其他数据类型直接添加
                                merged_data[key].extend(new_data[key])
                    
                    return merged_data
                except Exception as e:
                    print(color.yellow("[!] 读取或合并JSON数据出错，将创建新数据: " + str(e)))
                    # 如果读取失败，创建新的批量数据格式
                    batch_data = {
                        "scan_time": new_data["scan_time"],
                        "target_urls": [new_data["target_url"]],
                        "sensitive_info": new_data["sensitive_info"],
                        "high_risk_dirs": new_data["high_risk_dirs"],
                        "subdomains": new_data["subdomains"],
                        "chunk_js": new_data["chunk_js"],
                        "js_files": new_data["js_files"],
                        "images": new_data["images"],
                        "success_urls": new_data["success_urls"],
                        "other_urls": new_data["other_urls"],
                        "error_urls": new_data["error_urls"]
                    }
                    return batch_data
            else:
                # 如果文件不存在，创建新的批量数据格式
                batch_data = {
                    "scan_time": new_data["scan_time"],
                    "target_urls": [new_data["target_url"]],
                    "sensitive_info": new_data["sensitive_info"],
                    "high_risk_dirs": new_data["high_risk_dirs"],
                    "subdomains": new_data["subdomains"],
                    "chunk_js": new_data["chunk_js"],
                    "js_files": new_data["js_files"],
                    "images": new_data["images"],
                    "success_urls": new_data["success_urls"],
                    "other_urls": new_data["other_urls"],
                    "error_urls": new_data["error_urls"]
                }
                return batch_data
        except Exception as e:
            print(color.red_error() + "合并JSON数据时出错: " + str(e))
            # 如果发生异常，直接返回新数据
            return new_data
            
    def generate_frontend_html(self, output_path):
        """生成前端HTML文件（不再使用模板，直接内联所有HTML）"""
        # 读取当前模板文件的内容，并直接写入输出文件
        template_path = os.path.join(globals.get_value("ROOT_PATH"), "module", "report_template.html")
        try:
            with open(template_path, "r", encoding='utf-8') as f:
                html_content = f.read()
                
            # 修改HTML内容中的一些关键部分，使其适配批量URL扫描
            # 1. 修改标题
            html_content = html_content.replace('<title>JSFinderPlus 扫描报告</title>', 
                                            '<title>JSFinderPlus 批量扫描报告</title>')
            html_content = html_content.replace('<h1 class="mb-4 text-center">JSFinderPlus 扫描报告</h1>', 
                                            '<h1 class="mb-4 text-center">JSFinderPlus 批量扫描报告</h1>')
            
            # 2. 修改目标信息部分
            target_info_old = '''<div class="col-md-6">
                        <p><strong>目标网址:</strong> <span id="target-url"></span></p>
                        <p><strong>扫描时间:</strong> <span id="scan-time"></span></p>
                    </div>'''
            
            target_info_new = '''<div class="col-md-6">
                        <p><strong>批量扫描:</strong> <span id="target-count">0</span> 个目标</p>
                        <p><strong>扫描时间:</strong> <span id="scan-time"></span></p>
                        <div class="mt-2">
                            <select id="target-selector" class="form-select" onchange="filterDataByTarget(this.value)">
                                <option value="all">所有目标</option>
                            </select>
                        </div>
                    </div>'''
            
            html_content = html_content.replace(target_info_old, target_info_new)
            
            # 3. 修改JSON加载逻辑
            # 找到加载JSON的代码块的开始
            json_loading_start = "// 加载JSON数据"
            json_loading_end = "tryLoadJson(0);"
            
            # 在JavaScript中添加批量URL处理函数
            batch_url_functions = '''
                // 当前选中的目标URL
                let currentTargetFilter = 'all';
                
                // 根据选择的目标URL筛选数据
                function filterDataByTarget(targetUrl) {
                    currentTargetFilter = targetUrl;
                    console.log('筛选目标URL:', targetUrl);
                    
                    // 如果已加载数据，重新渲染
                    if (window.reportData) {
                        renderFilteredData(window.reportData, targetUrl);
                    }
                }
                
                // 渲染经过筛选的数据
                function renderFilteredData(data, targetUrl) {
                    // 创建筛选后的数据副本
                    const filteredData = {
                        scan_time: data.scan_time,
                        target_urls: data.target_urls,
                        sensitive_info: [],
                        high_risk_dirs: [],
                        subdomains: [],
                        chunk_js: [],
                        js_files: [],
                        images: [],
                        success_urls: [],
                        other_urls: [],
                        error_urls: []
                    };
                    
                    // 根据选择的目标URL筛选数据
                    if (targetUrl === 'all') {
                        // 全部数据
                        filteredData.sensitive_info = data.sensitive_info;
                        filteredData.high_risk_dirs = data.high_risk_dirs;
                        filteredData.subdomains = data.subdomains;
                        filteredData.chunk_js = data.chunk_js;
                        filteredData.js_files = data.js_files;
                        filteredData.images = data.images;
                        filteredData.success_urls = data.success_urls;
                        filteredData.other_urls = data.other_urls;
                        filteredData.error_urls = data.error_urls;
                    } else {
                        // 筛选指定目标的数据
                        filteredData.sensitive_info = data.sensitive_info.filter(item => item.url.includes(targetUrl));
                        filteredData.high_risk_dirs = data.high_risk_dirs.filter(item => item.url.includes(targetUrl));
                        filteredData.subdomains = data.subdomains.filter(item => item.url.includes(targetUrl));
                        filteredData.chunk_js = data.chunk_js.filter(item => item.url.includes(targetUrl));
                        filteredData.js_files = data.js_files.filter(item => item.url.includes(targetUrl));
                        filteredData.images = data.images.filter(item => item.url.includes(targetUrl));
                        filteredData.success_urls = data.success_urls.filter(item => item.url.includes(targetUrl));
                        filteredData.other_urls = data.other_urls.filter(item => item.url.includes(targetUrl));
                        filteredData.error_urls = data.error_urls.filter(item => item.url.includes(targetUrl));
                    }
                    
                    // 渲染筛选后的数据
                    renderReportDataInternal(filteredData);
                }
                
                // 内部渲染函数
                function renderReportDataInternal(data) {
                    // 清空所有表格
                    document.getElementById('sensitive-table').innerHTML = '';
                    document.getElementById('risk-table').innerHTML = '';
                    document.getElementById('subdomain-table').innerHTML = '';
                    document.getElementById('chunk-table').innerHTML = '';
                    document.getElementById('js-table').innerHTML = '';
                    document.getElementById('image-table').innerHTML = '';
                    document.getElementById('url-table').innerHTML = '';
                    
                    // 更新计数
                    try {
                        const sensitiveCount = data.sensitive_info ? data.sensitive_info.length : 0;
                        const riskCount = data.high_risk_dirs ? data.high_risk_dirs.length : 0;
                        const subdomainCount = data.subdomains ? data.subdomains.length : 0;
                        const chunkCount = data.chunk_js ? data.chunk_js.length : 0;
                        const jsCount = data.js_files ? data.js_files.length : 0;
                        const imageCount = data.images ? data.images.length : 0;
                        
                        updateElementCount('sensitive-count', sensitiveCount);
                        updateElementCount('risk-count', riskCount);
                        updateElementCount('subdomain-count', subdomainCount);
                        updateElementCount('chunk-count', chunkCount);
                        updateElementCount('js-count', jsCount);
                        updateElementCount('image-count', imageCount);
                        
                        const totalUrls = (data.success_urls ? data.success_urls.length : 0) +
                            (data.other_urls ? data.other_urls.length : 0) +
                            (data.error_urls ? data.error_urls.length : 0);
                        updateElementCount('url-count', totalUrls);
                    } catch (countError) {
                        console.error('更新计数时出错:', countError);
                    }
                    
                    // 渲染敏感信息表格
                    console.log('渲染敏感信息表格，数据条数:', data.sensitive_info ? data.sensitive_info.length : 0);
                    renderTable('sensitive-table', data.sensitive_info, item => {
                        return `
                            <td>${item.key || ''}</td>
                            <td><div class="full-content">${escapeHtml(item.match || '')}</div></td>
                            <td><div class="full-url">${item.url || ''}</div></td>
                            <td>${item.time || ''}</td>
                        `;
                    });
                    
                    // 渲染高危目录表格
                    renderTable('risk-table', data.high_risk_dirs, item => {
                        return `
                            <td><div class="full-url"><a href="${item.url || '#'}" target="_blank">${item.url || ''}</a></div></td>
                            <td><span class="badge ${getStatusBadgeClass(item.code)}">${item.code || ''}</span></td>
                            <td>${formatFileSize(item.size || 0)}</td>
                            <td>${item.time || ''}</td>
                        `;
                    });
                    
                    // 渲染子域名表格
                    renderTable('subdomain-table', data.subdomains, item => {
                        return `
                            <td>${item.url || ''}</td>
                            <td>${item.time || ''}</td>
                        `;
                    });
                    
                    // 渲染其他表格...
                    renderTable('chunk-table', data.chunk_js, item => {
                        return `
                            <td><div class="full-url"><a href="${item.url || '#'}" target="_blank">${item.url || ''}</a></div></td>
                            <td><span class="badge ${getStatusBadgeClass(item.code)}">${item.code || ''}</span></td>
                            <td>${formatFileSize(item.size || 0)}</td>
                            <td>${item.time || ''}</td>
                        `;
                    });
                    
                    renderTable('js-table', data.js_files, item => {
                        return `
                            <td><div class="full-url"><a href="${item.url || '#'}" target="_blank">${item.url || ''}</a></div></td>
                            <td><span class="badge ${getStatusBadgeClass(item.code)}">${item.code || ''}</span></td>
                            <td>${formatFileSize(item.size || 0)}</td>
                            <td>${item.time || ''}</td>
                        `;
                    });
                    
                    renderTable('image-table', data.images, item => {
                        return `
                            <td><div class="full-url"><a href="${item.url || '#'}" target="_blank">${item.url || ''}</a></div></td>
                            <td><img src="${item.url || ''}" class="img-preview" data-url="${item.url || ''}" alt="图片预览"></td>
                            <td><span class="badge ${getStatusBadgeClass(item.code)}">${item.code || ''}</span></td>
                            <td>${formatFileSize(item.size || 0)}</td>
                            <td>${item.time || ''}</td>
                        `;
                    });
                    
                    // 组合所有URL数据用于URL标签页
                    const allUrls = [
                        ...(data.success_urls || []).map(item => ({ ...item, category: 'success' })),
                        ...(data.other_urls || []).map(item => ({ ...item, category: 'other' })),
                        ...(data.error_urls || []).map(item => ({ ...item, category: 'error' }))
                    ];
                    
                    // 渲染URL表格
                    renderUrlTable(allUrls);
                    
                    // 存储URL数据用于筛选
                    window.allUrlsData = allUrls;
                    
                    // 设置图片预览等事件
                    setupEventListeners(data);
                }
            '''
            
            # 修改renderReportData函数
            render_report_data_start = "function renderReportData(data) {"
            render_report_data_new = '''function renderReportData(data) {
            window.reportData = data;
            console.log('加载数据成功');
            
            // 显示批量扫描信息
            if (data.target_urls && Array.isArray(data.target_urls)) {
                document.getElementById('target-count').textContent = data.target_urls.length;
                
                // 更新目标选择器下拉菜单
                const targetSelector = document.getElementById('target-selector');
                targetSelector.innerHTML = '<option value="all">所有目标</option>';
                
                data.target_urls.forEach(url => {
                    const option = document.createElement('option');
                    option.value = url;
                    option.textContent = url;
                    targetSelector.appendChild(option);
                });
            } else {
                document.getElementById('target-count').textContent = '1';
            }
            
            document.getElementById('scan-time').textContent = data.scan_time || '未提供';
            
            // 根据当前选中的目标进行筛选
            filterDataByTarget(currentTargetFilter);
        }'''
            
            # 替换加载JSON的逻辑
            modified_json_loading = '''
            // 加载JSON数据
            document.addEventListener('DOMContentLoaded', function () {
                console.log('页面加载完成，开始加载JSON数据...');
                
                // 确保下载按钮链接被正确设置
                document.getElementById('download-json').href = 'results.json';
                
                // 尝试加载JSON文件
                fetch('results.json')
                    .then(response => {
                        if (!response.ok) {
                            console.error(`加载JSON数据失败: ${response.status}`);
                            throw new Error(`网络响应不正常，状态码: ${response.status}`);
                        }
                        return response.text();
                    })
                    .then(text => {
                        if (!text || text.trim() === '') {
                            console.error('返回内容为空');
                            throw new Error('返回内容为空');
                        }
                        
                        try {
                            const data = JSON.parse(text);
                            console.log('JSON数据解析成功');
                            renderReportData(data);
                        } catch (e) {
                            console.error(`解析JSON失败: ${e.message}`);
                            throw new Error(`JSON格式无效: ${e.message}`);
                        }
                    })
                    .catch(error => {
                        console.error(`加载数据失败: ${error.message}`);
                        alert(`加载数据失败: ${error.message}\\n请确保results.json文件存在且格式正确。`);
                    });
            });
            
            ''' + batch_url_functions
            
            # 查找并替换renderReportData函数
            if render_report_data_start in html_content:
                # 找到函数的开始位置
                start_index = html_content.find(render_report_data_start)
                # 找到函数的结束大括号
                # 这需要一个更复杂的逻辑来匹配嵌套的括号，这里简化处理
                end_index = html_content.find("        // 辅助函数：更新元素计数", start_index)
                if end_index != -1:
                    # 替换整个函数
                    html_content = html_content[:start_index] + render_report_data_new + html_content[end_index:]
            
            # 查找并替换JSON加载逻辑
            if json_loading_start in html_content:
                start_index = html_content.find(json_loading_start)
                end_index = html_content.find(json_loading_end, start_index) + len(json_loading_end)
                if end_index != -1:
                    html_content = html_content[:start_index] + modified_json_loading + html_content[end_index:]
            
            # 确保输出目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # 写入修改后的HTML内容
            with open(output_path, "w", encoding='utf-8') as f:
                f.write(html_content)
                
            print(color.green("[*] 已生成HTML报告文件: {}".format(output_path)))
        except FileNotFoundError:
            print(color.red("[!] 模板文件不存在: {}".format(template_path)))
            # 创建一个基本的HTML文件作为备用
            html_content = """<!DOCTYPE html>
            <html>
            <head>
                <title>JSFinderPlus 批量扫描报告</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333; }
                    .error { color: red; }
                </style>
            </head>
            <body>
                <h1>JSFinderPlus 批量扫描报告</h1>
                <p class="error">模板文件缺失，无法生成完整报告。</p>
                <p>请检查 <code>module/report_template.html</code> 文件是否存在。</p>
                <p>您仍然可以查看 <a href="results.json">JSON数据</a>。</p>
            </body>
            </html>"""
            
            with open(output_path, "w", encoding='utf-8') as f:
                f.write(html_content)
        except Exception as e:
            print(color.red("[!] 生成HTML报告时出错: {}".format(str(e))))
