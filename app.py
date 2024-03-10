import os
import json
import time
import random
import nmap
from dotenv import load_dotenv
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from wakeonlan import send_magic_packet
import threading

# 加载环境变量
load_dotenv(override=True)

# 从环境变量获取配置
MQTT_SERVER = os.getenv("MQTT_SERVER")
MQTT_PORT = int(os.getenv("MQTT_PORT", 8883))  # 默认端口为8883
MQTT_TOPIC_SUBSCRIBE = os.getenv("MQTT_TOPIC_SUBSCRIBE")
MQTT_TOPIC_PUBLISH = os.getenv("MQTT_TOPIC_PUBLISH")
MQTT_USERNAME = os.getenv("MQTT_USERNAME")  # MQTT服务器的用户名
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")  # MQTT服务器的密码

HEARTBEAT_INTERVAL = 1


def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe(MQTT_TOPIC_SUBSCRIBE)

def on_message(client, userdata, msg):
    print(f"Message received-> {msg.topic} {str(msg.payload)}")
    try:
        command = json.loads(msg.payload.decode())
        if command['action'] == 'wake':
            send_wol(command['mac'])
        elif command['action'] == 'status':
            report_status(command['mac'])
        elif command['action'] == 'list_devices':
            list_devices_from_arp()
    except Exception as e:
        print(f"Error processing message: {e}")

def send_wol(mac):
    send_magic_packet(mac)
    print(f"WOL packet sent to {mac}")

def find_ip_by_mac(target_mac):
    with open('/proc/net/arp', 'r') as f:
        for line in f.readlines()[1:]:  # 跳过第一行标题
            parts = line.split()
            ip_address = parts[0]
            mac_address = parts[3]
            if mac_address.upper() == target_mac.upper():
                return ip_address
    return None

def report_status(mac):
    ip = find_ip_by_mac(mac)
    if ip is None:
        print(f"Device with MAC {mac} not found.")
        # 设备未找到时也上报一条消息
        status_message = json.dumps({'mac': mac, 'ip': 'unknown', 'hostname': 'unknown', 'status': 'unknown'})
        client.publish(MQTT_TOPIC_PUBLISH, status_message)
        return
    
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-sP')  # 对单个IP执行ping扫描
        if nm.all_hosts():  # 检查是否有扫描结果
            status = 'up' if nm[ip].state() == 'up' else 'down'
            hostname = nm[ip].hostname() if nm[ip].hostname() else 'unknown'
        else:
            status = 'down'
            hostname = 'unknown'
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        status = 'unknown'
        hostname = 'unknown'
    
    status_message = json.dumps({'mac': mac, 'ip': ip if ip else 'unknown', 'hostname': hostname, 'status': status})
    client.publish(MQTT_TOPIC_PUBLISH, status_message)



def list_devices_from_arp():
    devices = []
    nm = nmap.PortScanner()
    
    with open('/proc/net/arp', 'r') as f:
        for line in f.readlines()[1:]:  # 跳过第一行标题
            parts = line.split()
            ip_address = parts[0]
            mac_address = parts[3]
            if mac_address != '00:00:00:00:00:00':  # 忽略空MAC地址
                # 对每个IP地址进行nmap扫描以获取更多信息
                try:
                    nm.scan(hosts=ip_address, arguments='-sP')
                    hostname = nm[ip_address].hostname()
                    status = nm[ip_address].state()
                except Exception as e:
                    print(f"Error scanning {ip_address}: {e}")
                    hostname = 'unknown'
                    status = 'unknown'
                
                devices.append({'ip': ip_address, 'mac': mac_address, 'hostname': hostname, 'status': status})
    
    client.publish(MQTT_TOPIC_PUBLISH, json.dumps({'devices': devices}))


def send_heartbeat():
    while True:
        ip_list = os.popen('hostname -I').read().strip().split()
        ipv4_address = ip_list[0] if ip_list else 'N/A'
        hostname = os.popen('hostname').read().strip()
        client.publish(MQTT_TOPIC_PUBLISH, json.dumps({'heartbeat': {'hostname': hostname, 'ip': ipv4_address}}))
        time.sleep(HEARTBEAT_INTERVAL)

client_id = f'wolclient-{random.randint(0, 1000)}'
client = mqtt.Client(client_id=client_id, callback_api_version=CallbackAPIVersion.VERSION1, protocol=mqtt.MQTTv311)
client.tls_set()  # 启用TLS

if MQTT_USERNAME and MQTT_PASSWORD:  # Check if both MQTT_USERNAME and MQTT_PASSWORD are not empty strings
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)  # 设置用户名和密码

client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_SERVER, MQTT_PORT, 60)

heartbeat_thread = threading.Thread(target=send_heartbeat)
heartbeat_thread.daemon = True
heartbeat_thread.start()

client.loop_forever()
