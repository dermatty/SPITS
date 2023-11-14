import http.server
import socketserver
import os, sys, signal, time, datetime
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
		# sys.exit()

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

	fileslist = []
	for file in os.listdir(logdir):
		if file.startswith("20") and file.endswith(".log"):
			fileslist.append(file)

	MAX_N = 10
	n = 0
	trails = []
	fileslist.sort(reverse=True,key=lambda date: datetime.datetime.strptime(date.split(".log")[0], "%Y-%m-%d"))
	for file in fileslist:
		if n >= MAX_N:
			break
		n += 1
		file_incl_path = logdir + file
		with open(file_incl_path, "r") as f:
			lines = f.readlines()
		fileips = [l.split()[3]+"\n" for l in lines if "known attacker" in l]
		trails.extend(fileips)
		print("##### " + file + " " + "######: ", len(fileips))

	print("Len trails: ", len(trails))
	trails_wo_duplicates = list(set(trails))
	trails_wo_duplicates2 = [x for i, x in enumerate(trails) if x not in trails[:i]]
	print("Len trails_wo_duplicates: ", len(trails_wo_duplicates))
	# and insert into html date
	for i, t in enumerate(trails_wo_duplicates):

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
	maindir = expanduser("~") + "/spits"
	if not os.path.exists(maindir):
		os.makedirs(maindir)

	print("Press Ctrl-c key to stop")

	mtime = {}
	while not SH.stopped:
		mtime, rescan = checkmtime(logdir, mtime)
		if rescan:
			print("Maltrail logs changed, rescanning log directory ...")
			scan_maltrail_logs(indexhtml, logdir)
		for _ in range(10):
			try:
				time.sleep(0.5)
			except KeyboardInterrupt:
				break
	print("Stopped!")
