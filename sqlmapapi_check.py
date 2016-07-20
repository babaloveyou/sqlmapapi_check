# -*- coding: utf-8 -*-
"""
sqlmap注入过程管理脚本，可控制超时时间及检测到可能有waf无法注入后自动跳出
"""
import os
import sys
import json
import time
import requests


def usage():
	print '+' + '-' * 50 + '+'
	print '\t   Python sqlmapapi_test'
	print '\t\t Code BY:YIYANG'
	print '+' + '-' * 50 + '+'
	if len(sys.argv) != 2:
		print "example: sqlmapapi.py url.txt"
		sys.exit()

def task_new(server):
	url = server + '/task/new'
	req = requests.get(url)
	taskid = req.json()['taskid']
	success = req.json()['success']
	return (success,taskid)

def task_start(server,taskid,data,headers):
	url = server + '/scan/' + taskid + '/start'
	req = requests.post(url,json.dumps(data),headers = headers)
	success = req.json()['success']
	return success

def task_status(server,taskid):
	url = server + '/scan/' + taskid + '/status'
	req = requests.get(url)
	status_check = req.json()['status']
	return status_check

def task_log(server,taskid):
	url = server + '/scan/' + taskid + '/log'
	req = requests.get(url).text
	scan_json = json.loads(req)['log']
	flag1 = 0
	if scan_json:
		print scan_json[-1]['message']
		if 'retry' in scan_json[-1]['message']:
			flag1 = 1
		else:
			flag1 = 0
	return flag1

def task_data(server,taskid):
	url = server + '/scan/' + taskid + '/data'
	req = requests.get(url)
	vuln_data = req.json()['data']
	if len(vuln_data):
		vuln = 1
	else:
		vuln = 0
	return vuln

def task_stop(server,taskid):
	url = server + '/scan/' + taskid + '/stop'
	req = requests.get(url)
	success = req.json()['success']
	return success

def task_kill(server,taskid):
	url = server + '/scan/' + taskid + '/kill'
	req = requests.get(url)
	success = req.json()['success']
	return success

def task_delete(server,taskid):
	url = server + '/scan/' + taskid + '/delete'
	requests.get(url)

def get_url(urls):
	newurl = []
	for url in urls:
		if '?' in url:
			newurl.append(url)
	return newurl

if __name__ == "__main__":
	usage()
	targets = [x.rstrip() for x in open(sys.argv[1])]
	targets = get_url(targets)
	server = 'http://127.0.0.1:8775'
	headers = {'Content-Type':'application/json'}
	i= 0
	vuln = []

	for target in targets:
		try:
			data = {"url":target,'batch':True,'randomAgent':True,'tamper':'space2comment','tech':'BT','timeout':15,'level':1}
			i = i + 1
			flag = 0

			(new,taskid) = task_new(server)
			if new:
			  print "scan created"
			if not new:
				print "create failed"
			start = task_start(server,taskid,data,headers)
			if start:
				print "--------------->>> start scan target %s" % i
			if not start:
				print "scan can not be started"

			while start:
				start_time = time.time()
				status = task_status(server,taskid)
				if status == 'running':
					print "scan running:"
				elif status == 'terminated':
					print "scan terminated\n"
					data = task_data(server,taskid)
					if data:
						print "--------------->>> congratulation! %s is vuln\n" % target
						vuln.append(target)
					if not data:
						print "--------------->>> the target is not vuln\n"
					task_delete(server,taskid)
					break
				else:
					print "scan get some error"
					break

				time.sleep(10)
				flag1 = task_log(server,taskid)
				flag = (flag + 1)*flag1

				if (time.time() - start_time > 300) or (flag == 5):  #此处设置检测超时时间，以及链接超时次数
					print "there maybe a strong waf or time is over,i will abandon this target."
					stop = task_stop(server,taskid)
					if stop:
						print "scan stoped"
					if not stop:
						print "the scan can not be stopped"
					kill = task_kill(server,taskid)
					task_delete(server,taskid)
					if kill:
						print "scan killed"
					if not kill:
						print "the scan can not be killed"
					break
		except:
			pass

	for each in vuln:
		print each + '\n'
