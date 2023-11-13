import http.server
import socketserver
import os, sys, signal, time
import multiprocessing
from os.path import expanduser

__version__ = "0.1"


class SigHandler:
	def __init__(self, mp):
		self.mp = mp
		self.stopped = False

	def sighandler(self, a, b):
		self.stop()

	def stop(self):
		for m in self.mp:
			m.terminate()
			m.join()
		self.stopped = True


def webserver_process(port):
	with socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
		# print("serving at port", PORT)
		httpd.serve_forever()


def scan_maltrail_logs(indexhtml, logdir):
	with open(indexhtml, "r") as f:
		contents = f.readlines()

	# remove ips from content
	i_start = -1
	i_end = -1
	for i, c in enumerate(contents):
		if (not c.strip().startswith("<")) and i_start == -1:
			i_start = i
		if i_start != -1 and c.strip().startswith("</pre>"):
			i_end = i
			break
	for i in range(i_start, i_end):
		contents.pop(i_start)

	# read log ips
	file = logdir + "2023-11-12.log"
	with open(file, "r") as f:
		lines = f.readlines()
	trails = [l.split()[3]+"\n" for l in lines if "known attacker" in l]

	# and insert into html date
	for i, t in enumerate(trails):
		contents.insert(i_start+i, t)

	# and write to html file
	with open(indexhtml, "w") as f:
		f.writelines(contents)


def start():

	print(os.getcwd())
	indexhtml = os.getcwd() + "/index.html"
	logdir = expanduser("~") + "/var_log_maltrail/"

	scan_maltrail_logs(indexhtml, logdir)

	mp_webserver = multiprocessing.Process(target=webserver_process, args=(8001,))
	mp_webserver.daemon = True
	mp_webserver.start()

	sh = SigHandler([mp_webserver])
	signal.signal(signal.SIGINT, sh.sighandler)
	signal.signal(signal.SIGTERM, sh.sighandler)

	print("Press Ctrl-c key to stop")

	while not sh.stopped:
		time.sleep(5)

	print("Stopped!")
