# -*- coding: utf_8 -*-

import os
import sys
import json
import time
import requests


def usage():
	print '+' + '-' * 50 + '+'
	print '\t   Python sqlmapapi_test_tool'
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


if __name__ == "__main__":
	usage()
	targets = [x.rstrip() for x in open(sys.argv[1])]
	server = 'http://127.0.0.1:8775'
	headers = {'Content-Type':'application/json'}

	for target in targets:
		try:
			data = {"url":target,'smart':True}#你可以安需求增加修改sqlmap选项
			start_time = time.time()

			(new,taskid) = task_new(server)
			if new:
			  print "scan created"
			if not new:
				print "create failed"
			start = task_start(server,taskid,data,headers)
			if start:
				print "scan started"
			if not start:
				print "scan can not be started"

			while start:
				status = task_status(server,taskid)
				if status == 'running':
					print "scan running"
				elif status == 'terminated':
					print "scan terminated\n"
					data = task_data(server,taskid)
					if data:
						print "%s is vuln" % target
					if not data:
						print "the target is not vuln"
					task_delete(server,taskid)
					break
				else:
					print "scan get some error"
					break
				time.sleep(10)
				if time.time() - start_time > 3000:
					print "the scan over time"
					stop = task_stop(server,taskid)
					if stop:
						print "scan stoped"
					if not stop:
						print "the scan can not be stopped"
					kill = task_kill(server,taskid)
					if kill:
						print "scan killed"
					if not kill:
						print "the scan can not be killed"
					break
		except:
			pass
