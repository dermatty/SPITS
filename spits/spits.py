import http.server
import socketserver
import os, sys, signal, time
import multiprocessing
from os.path import expanduser

__version__ = "0.1"


def webserver_process(port):
	with socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
		# print("serving at port", PORT)
		httpd.serve_forever()


class SigHandler:
	def __init__(self, mplist):
		self.mplist = mplist
		self.stopped = False

	def sighandler(self, a, b):
		self.stop()
		sys.exit()

	def stop(self):
		print("sighandler stopping mps ...")
		for m in self.mplist:
			m.terminate()
			m.join()
		print("... mps stopped!")
		self.stopped = True


MP = multiprocessing.Process(target=webserver_process, args=(8002,))
MP.daemon = True
MP.start()
SH = SigHandler([MP])


def checkmtime (path, oldmtime):
	mtime0 = {}
	for file in os.listdir(path):
		if file.startswith("20") and file.endswith("log"):
			mtime0[file] = os.path.getmtime(path + file)
	if not (oldmtime == mtime0):
		return mtime0, True
	return mtime0, False


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

	global MP, SH

	signal.signal(signal.SIGINT, SH.sighandler)
	signal.signal(signal.SIGTERM, SH.sighandler)

	indexhtml = os.getcwd() + "/index.html"
	logdir = expanduser("~") + "/var_log_maltrail/"

	scan_maltrail_logs(indexhtml, logdir)

	print("Press Ctrl-c key to stop")

	mtime = {}
	while not SH.stopped:
		mtime, rescan = checkmtime(logdir, mtime)
		if rescan:
			print("Maltrail logs changed, rescanning log directory ...")
			scan_maltrail_logs(indexhtml, logdir)
		time.sleep(5)

	print("Stopped!")
