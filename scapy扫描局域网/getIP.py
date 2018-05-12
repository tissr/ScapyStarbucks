import os
import re
from scapy.all import *
from scapy.layers import l2
import json
import time
from macpy import Mac
# A类地址：10.0.0.0--10.255.255.255
# B类地址：172.16.0.0--172.31.255.255 
# C类地址：192.168.0.0--192.168.255.255

def get_all_ip_range():
	result = []
	ip_des_list = os.popen("ifconfig | grep inet").readlines()
	for ip_des in ip_des_list:
		try:
			if re.match(r'\tinet[^6]([0-9]{1,3}).*', ip_des).group(1) in ["192", "172", "10"]:
				ip_des = re.match(r'\tinet[^6]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*', ip_des).group(1)
				ip_range = re.match(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.', ip_des).group()
				result.append(ip_range)
		except:
			pass
	return result


def getIPAndMac(ip_range):
	result_list = {}
	for ip in ip_range:
		# 打印生成的目标IP
		print("=检测ip=>", ip)
		# 根据目标IP组包, ICMP可以看做Ping, 程序员式招呼
		p = IP(dst=ip)/ICMP()/b'HelloWorld'
		# 将数据包发出, 等待0.3秒,无回应则放弃等待, 屏蔽提示消息
		r = sr1(p, timeout=0.3, verbose = False)
		# 如果收到了返回的数据包,则存到一个数组中
		try:
			if r.getlayer(IP).fields['src'] == ip and r.getlayer(ICMP).fields['type'] == 0:
				net_info = {}
				mac = l2.getmacbyip(ip)
				getcom = Mac()
				com = getcom.search(mac)
				mac = mac+ "|" + str(com)
				result_list[str(ip)] = mac
				print("成功获取一个mac地址:", ip, mac)
		except Exception as e:
			pass
	return result_list


def select_ip_range(all_ip_range):
	choose_ip_dic = {}
	for index, ip_range in enumerate(all_ip_range):
		all_ip = []
		for num in range(256):
			all_ip.append(ip_range+str(num))

		choose_ip_dic[index] = all_ip

	index_list = []
	for index, ip_range in enumerate(all_ip_range):
		index_list.append(index)
		print("序列号:", index, "ip范围", ip_range+"0"+"-"+ip_range+"255")
	print(index_list)
	while 1:
		user_choose = input("请输入您需要扫描的ip范围序号:")
		try:
			user_choose = int(user_choose)
		except:
			print("请您输入数字!!!")
			pass
		if user_choose in index_list:
			user_ip_list = choose_ip_dic[int(user_choose)]
			break
		else:
			print("您的输入有误, 请查正后输入!!!")
	return user_ip_list

def genderTxt(result_dic):
	file_name = time.strftime("%Y%m%d%H%M%S")+"IPAndMac.txt"
	print(file_name)
	for key in result_dic:
		with open(file_name, "a") as f:
			f.write("设备的IP:"+key+" Mac地址"+result_dic[key]+"\n")

	result_json = json.dumps(result_dic, ensure_ascii=False)

def main():
	all_ip_range = get_all_ip_range()
	ip_range = select_ip_range(all_ip_range)
	print(ip_range)
	result_dic = getIPAndMac(ip_range)
	# result_dic = {"k1": "001", "k123": "msdf", "k213": "00213"}
	genderTxt(result_dic)

if __name__ == '__main__':
	main()