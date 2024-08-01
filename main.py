import socket
import requests
import sys

# 定义需要检查的服务及其端口和未授权访问URL
services = {
    "Weblogic": [7001, ["http://{target}:7001/console", "https://{target}:7001/console"]],
    "Elasticsearch": [9200, 9300, ["http://{target}:9200", "https://{target}:9200", "http://{target}:9300", "https://{target}:9300"]],
    "MongoDB": [27017, []],
    "Redis": [6379, []],
    "Zabbix": [10051, []],
    "Druid": [[], ["http://{target}:8082/druid", "https://{target}:8082/druid"]],
    "JBoss": [8080, ["http://{target}:8080", "https://{target}:8080"]],
    "Active MQ": [8161, ["http://{target}:8161", "https://{target}:8161"]],
    "Apache Spark": [6066, 8081, 8082, ["http://{target}:6066", "https://{target}:6066", "http://{target}:8081", "https://{target}:8081", "http://{target}:8082", "https://{target}:8082"]],
    "Atlassian Crowd": [[], ["http://{target}:8095/crowd", "https://{target}:8095/crowd"]],
    "CouchDB": [5984, ["http://{target}:5984/_utils", "https://{target}:5984/_utils"]],
    "Docker Registry": [5000, ["http://{target}:5000/v2/", "https://{target}:5000/v2/"]],
    "Docker": [2375, []],
    "Dubbo": [28096, ["http://{target}:28096", "https://{target}:28096"]],
    "FTP": [21, []],
    "HadoopYARN": [8088, ["http://{target}:8088", "https://{target}:8088"]],
    "Harbor": [[], ["http://{target}/harbor/sign-in", "https://{target}/harbor/sign-in"]],
    "Jenkins": [8080, ["http://{target}:8080", "https://{target}:8080"]],
    "Kibana": [5601, ["http://{target}:5601", "https://{target}:5601"]],
    "Kubernetes Api Server": [8080, 10250, ["http://{target}:8080", "https://{target}:8080", "https://{target}:10250"]],
    "LDAP": [389, []],
    "Memcached": [11211, []],
    "NFS": [2049, 20048, []],
    "PHP-FPM Fastcgi": [[], ["http://{target}/status", "https://{target}/status"]],
    "RabbitMQ": [15672, 15692, 25672, ["http://{target}:15672", "https://{target}:15672", "http://{target}:15692", "https://{target}:15692", "http://{target}:25672", "https://{target}:25672"]],
    "Rsync": [873, []],
    "Solr": [[], ["http://{target}:8983/solr", "https://{target}:8983/solr"]],
    "SpringBoot Actuator": [[], ["http://{target}:8080/actuator", "https://{target}:8080/actuator"]],
    "SwaggerUI": [[], ["http://{target}:8080/swagger-ui.html", "https://{target}:8080/swagger-ui.html"]],
    "ThinkAdminV6": [[], ["http://{target}/admin", "https://{target}/admin"]],
    "VNC": [5900, 5901, []],
    "WordPress": [[], ["http://{target}/wp-admin", "https://{target}/wp-admin"]],
    "ZooKeeper": [2181, []],
    "宝塔phpmyadmin": [[], ["http://{target}:8888/phpmyadmin", "https://{target}:8888/phpmyadmin"]],
}

# 定义目标和超时时间
timeout = 20

# 检查端口是否开放（基于域名）
def check_port_domain(domain, port):
    try:
        sock = socket.create_connection((domain, port), timeout=1)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, socket.gaierror):
        return False

# 检查端口是否开放（基于IP地址）
def check_port_ip(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((ip, port))
    except socket.error:
        return False
    return True

# 尝试HTTP访问
def check_http_access(url):
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return True
    except requests.RequestException:
        return False
    return False

# 扫描所有服务（基于域名）
def scan_services_domain(domain):
    for service, (ports, urls) in services.items():
        for port in ports:
            if check_port_domain(domain, port):
                print(f"[WARNING] {service} 未授权访问可能存在，端口: {port}")
            else:
                print(f"{service} 端口 {port} 未开放")

        for url_template in urls:
            url = url_template.format(target=domain)
            if check_http_access(url):
                print(f"[CRITICAL] {service} 未授权HTTP访问: {url}")

# 扫描所有服务（基于IP地址）
def scan_services_ip(ip):
    for service, (ports, urls) in services.items():
        for port in ports:
            if check_port_ip(ip, port):
                print(f"[WARNING] {service} 未授权访问可能存在，端口: {port}")
            else:
                print(f"{service} 端口 {port} 未开放")

        for url_template in urls:
            url = url_template.format(target=ip)
            if check_http_access(url):
                print(f"[CRITICAL] {service} 未授权HTTP访问: {url}")

# 主函数，根据命令行参数执行扫描
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python script.py [domain|ip] <目标>")
        sys.exit(1)

    scan_type = sys.argv[1]
    target = sys.argv[2]

    if scan_type == "domain":
        scan_services_domain(target)
    elif scan_type == "ip":
        scan_services_ip(target)
    else:
        print("无效的扫描类型。请选择 'domain' 或 'ip'。")
        sys.exit(1)

    print("扫描完成。")
