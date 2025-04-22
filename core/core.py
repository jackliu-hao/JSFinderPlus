import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from module import globals
from module.color import color

requests.packages.urllib3.disable_warnings()


class Core(object):
    leak_info_patterns = {
        'Mail': r'(([a-zA-Z0-9][_|\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\.])*[a-zA-Z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,}))',
        'Swagger UI': r'((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi))',
        'Druid': r'((Druid Stat Index)|(druid monitor))',
        'URL As A Value': r'(=(https?://.*|https?%3(a|A)%2(f|F)%2(f|F).*))',
        'Spring Boot': r'((local.server.port)|(:{\"mappings\":{\")|({\"_links\":{\"self\":))',
        'IDCard': '[^0-9]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))[^0-9]',
        'Phone': '[^0-9A-Za-z](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})[^0-9A-Za-z]',
        'Internal IP Address': '[^0-9]((127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))',
        'Password': r"(?i)("r"password\s*[`=:\"]+\s*[^\s]+|"r"password is\s*[`=:\"]*\s*[^\s]+|"r"pwd\s*[`=:\"]*\s*[^\s]+|"r"passwd\s*[`=:\"]+\s*[^\s]+)",
        
    }
    # 'ChunkJS': r'\"chunk-[a-zA-Z0-9]+\":\"[a-zA-Z0-9]+\"'
    chunk_js_pattern = r'\"chunk-[a-zA-Z0-9]+\":\"[a-zA-Z0-9]+\"'

    # 匹配敏感信息
    @staticmethod
    def find_leak_info(url, text):
        # 确保leak_infos_match已初始化
        if globals.get_value("leak_infos_match") is None:
            globals.set_value("leak_infos_match", [])
            print("初始化leak_infos_match列表")
            
        for k in Core.leak_info_patterns.keys():
            pattern = Core.leak_info_patterns[k]
            try:
                matchs = re.findall(pattern, text, re.IGNORECASE)
                if matchs:  # 只处理有匹配结果的情况
                    for match in matchs:
                        # 确保匹配结果是字符串
                        match_str = match[0] if isinstance(match, tuple) else str(match)
                        
                        # 创建匹配结果元组
                        match_tuple = (k, match_str, url)
                        
                        # 检查是否已存在此匹配
                        existing_matches = globals.get_value("leak_infos_match")
                        is_duplicate = False
                        for existing in existing_matches:
                            if existing[0] == k and existing[1] == match_str and existing[2] == url:
                                is_duplicate = True
                                break
                        
                        # 仅添加非重复的匹配结果
                        if not is_duplicate:
                            globals.get_value("leak_infos_match").append(match_tuple)
                            # 使用元组(3, url, code, text)格式发送到输出队列
                            globals.get_value("OUT_QUEUE").put((3, url, 0, match_tuple))
                            print(color.blue("[-] Find leak info ==> {}: {} in {}".format(k, match_str, url)))
            except Exception as e:
                print(color.red_error() + "Leak info extraction error: " + str(e))

    # Regular expression comes from https://github.com/GerbenJavado/LinkFinder
    @staticmethod
    def extract_URL(JS):
        pattern_raw = r"""
    	  (?:"|')                               # Start newline delimiter
    	  (
    	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
    	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    	    |
    	    ((?:/|\.\./|\./)                    # Start with /,../,./
    	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
    	    |
    	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
    	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    	    |
    	    ([a-zA-Z0-9_\-]{1,}                 # filename
    	    \.(?:php|asp|aspx|jsp|json|
    	         action|html|js|txt|xml)             # . + extension
    	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
    	  )
    	  (?:"|')                               # End newline delimiter
    	"""
        pattern = re.compile(pattern_raw, re.VERBOSE)
        result = re.finditer(pattern, str(JS))
        if result == None:
            return []
        js_url = []
        return [match.group().strip('"').strip("'") for match in result
                if match.group() not in js_url]

    # Get the page source
    @staticmethod
    def Extract_html(URL):
        header = globals.get_value("HEADERS")
        try:
            req = requests.get(URL, headers=header, timeout=3, verify=False)
            raw = req.content.decode("utf-8", "ignore")
            return raw, req.status_code
        except:
            print(color.red_error() + "REQUEST ERROR：" + URL)
            return "", 0

    # Handling relative URLs
    @staticmethod
    def process_url(URL, re_URL):
        black_url = ["javascript:"]  # Add some keyword for filter url.
        URL_raw = urlparse(URL)
        ab_URL = URL_raw.netloc
        host_URL = URL_raw.scheme
        if re_URL[0:2] == "//":
            result = host_URL + ":" + re_URL
        elif re_URL[0:4] == "http":
            result = re_URL
        elif re_URL[0:2] != "//" and re_URL not in black_url:
            if re_URL[0:1] == "/":
                if globals.get_value("SITE_ROOT"):
                    result = globals.get_value("SITE_ROOT") + re_URL
                else:
                    result = host_URL + "://" + ab_URL + re_URL
            else:
                if re_URL[0:1] == ".":
                    if re_URL[0:2] == "..":
                        if globals.get_value("SITE_ROOT"):
                            result = globals.get_value("SITE_ROOT") + re_URL[2:]
                        else:
                            result = host_URL + "://" + ab_URL + re_URL[2:]
                    else:
                        if globals.get_value("SITE_ROOT"):
                            result = globals.get_value("SITE_ROOT") + re_URL[1:]
                        else:
                            result = host_URL + "://" + ab_URL + re_URL[1:]

                else:
                    if globals.get_value("SITE_ROOT"):
                        result = globals.get_value("SITE_ROOT") + "/" + re_URL
                    else:
                        result = host_URL + "://" + ab_URL + "/" + re_URL

        else:
            result = URL
        return result

    @staticmethod
    def find_last(string, str):
        positions = []
        last_position = -1
        while True:
            position = string.find(str, last_position + 1)
            if position == -1: break
            last_position = position
            positions.append(position)
        return positions

    @staticmethod
    def find_by_url(html_raw, url):
        if html_raw is None:
            return []
        # print(html_raw)
        html = BeautifulSoup(html_raw, "html.parser")
        html_scripts = html.findAll("script")
        script_array = {}
        script_temp = ""
        allurls = []
        for html_script in html_scripts:
            script_src = html_script.get("src")
            if script_src:
                purl = Core.process_url(url, script_src)
                allurls.append(purl)

        # 正则找url
        temp_urls = Core.extract_URL(html_raw)
        for temp_url in temp_urls:
            allurls.append(Core.process_url(url, temp_url))
        # 查找敏感信息
        Core.find_leak_info(url, html_raw)
        # 查找chunk-xxx格式的JS文件
        Core.find_chunk_js(url, html_raw)
        result = []
        for singerurl in allurls:
            url_raw = urlparse(url)
            domain = url_raw.netloc
            positions = Core.find_last(domain, ".")
            miandomain = domain
            if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
            # print(miandomain)
            suburl = urlparse(singerurl)
            subdomain = suburl.netloc
            # print(singerurl)
            if miandomain in subdomain or subdomain.strip() == "":
                if singerurl.strip() not in result:
                    result.append(singerurl)
        # 查找子域名
        subdomains = Core.find_subdomain(result, globals.get_value("URL"))
        if subdomains:
            for subdomain in subdomains:
                if subdomain not in globals.get_value("SUBDOMIAN_LIST"):
                    globals.get_value("SUBDOMIAN_LIST").append(subdomain)

        return result

    @staticmethod
    def find_subdomain(urls, mainurl):
        url_raw = urlparse(mainurl)
        domain = url_raw.netloc
        miandomain = domain
        positions = Core.find_last(domain, ".")
        if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
        subdomains = []
        for url in urls:
            suburl = urlparse(url)
            subdomain = suburl.netloc
            # print(subdomain)
            if subdomain.strip() == "": continue
            if miandomain in subdomain:
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
        return subdomains

    @staticmethod
    def find_by_url_deep(html_raw, url):
        if html_raw is None:
            return []
        html = BeautifulSoup(html_raw, "html.parser")
        html_as = html.findAll("a")
        links = []
        for html_a in html_as:
            src = html_a.get("href")
            if src == "" or src == None: continue
            link = Core.process_url(url, src)
            if link not in links:
                links.append(link)
        if links == []: return []
        result = []
        for singerurl in links:
            url_raw = urlparse(url)
            domain = url_raw.netloc
            positions = Core.find_last(domain, ".")
            miandomain = domain
            if len(positions) > 1: miandomain = domain[positions[-2] + 1:]
            # print(miandomain)
            suburl = urlparse(singerurl)
            subdomain = suburl.netloc
            # print(singerurl)
            if miandomain in subdomain or subdomain.strip() == "":
                if singerurl.strip() not in result:
                    result.append(singerurl)

        return result

    @staticmethod
    def find_chunk_js(url, text):
        """
        在JS文本中查找chunk-xxx格式的JS文件，包括"chunk-xxxx":"yyyy"格式
        """
        try:
        
            matches = re.findall(Core.chunk_js_pattern, text, re.IGNORECASE)
            
            # 如果找到匹配项，只添加一次这个JS文件的URL
            if matches:
                # 只取第一个匹配到的chunk作为示例
                chunk_id = re.search(r'chunk-[a-zA-Z0-9]+', matches[0]).group(0)
                match_tuple = ("ChunkJS", chunk_id, url)
                # globals.get_value("leak_infos_match").append(match_tuple)
                globals.get_value("OUT_QUEUE").put((5, url, -1, "{}".format(match_tuple)))
                print(color.blue("[-] Find ChunkJS in file ==> {} (total matches: {})".format(url, len(matches))))
        except Exception as e:
            pass
