import http.server
import socketserver
import os, sys, signal, time, datetime
import multiprocessing
from os.path import expanduser
import configparser
import logging
from importlib import metadata

import toml

# this only gives the version of the last pip installation of "app"
package = "spits"

if os.getcwd() == "/media/nfs/development/GIT/SPITS":
	__version__ = toml.load("pyproject.toml")["tool"]["poetry"]["version"] + "_dev"
else:
	__version__ = metadata.version(package)


def webserver_process(port, directory):

	class Handler(http.server.SimpleHTTPRequestHandler):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, directory=directory, **kwargs)

	socketserver.TCPServer.allow_reuse_address = True
	with socketserver.TCPServer(("", int(port)), Handler) as httpd:
		# print("serving at port", PORT)
		httpd.serve_forever()


class SigHandler:
	def __init__(self, mplist, logger):
		self.mplist = mplist
		self.logger = logger
		self.stopped = False

	def sighandler(self, a, b):
		self.stop()
		# sys.exit()

	def stop(self):
		self.logger.info("sighandler stopping mps ...")
		for m in self.mplist:
			m.terminate()
			m.join()
		self.logger.info("... mps stopped!")
		self.stopped = True
		self.logger.info("Exited! (sighandler)")
		sys.exit(0)


def checkmtime (path, oldmtime):
	mtime0 = {}
	for file in os.listdir(path):
		if file.startswith("20") and file.endswith("log"):
			mtime0[file] = os.path.getmtime(path + file)
	if not (oldmtime == mtime0):
		return mtime0, True
	return mtime0, False


def scan_logs(max_logs, indexhtml, logdir, g3_logfile, logger):
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

	# read maltrail log ips
	fileslist = []
	for file in os.listdir(logdir):
		if file.startswith("20") and file.endswith(".log"):
			fileslist.append(file)
	n = 0
	trails = []
	fileslist.sort(reverse=True,key=lambda date: datetime.datetime.strptime(date.split(".log")[0], "%Y-%m-%d"))
	for file in fileslist:
		if n >= max_logs:
			break
		n += 1
		file_incl_path = logdir + file
		with open(file_incl_path, "r") as f:
			lines = f.readlines()
		fileips0 = [l.split()[3]+"\n" for l in lines if "known attacker" in l]
		fileips = list(set(fileips0))
		trails.extend(fileips)
		logger.debug("Log file " + file + " " + ", # ips (raw / adjusted): " + str(len(fileips0)) + " / " +
					 str(len(fileips)))

	# read gcuk_logdir
	with open(g3_logfile, "r") as f:
		lines = f.readlines()
	g3trails = [l.split()[8][3:-1] + "\n" for l in lines if "Invalid request from ip" in l]
	g3trails_wo_duplicates = list(set(g3trails))

	nr_trails_unadjusted = len(trails)
	trails.extend(g3trails_wo_duplicates)
	nr_trails_incl_g3 = len(trails)
	trails_wo_duplicates = list(set(trails))
	nr_trails_adjusted = len(trails_wo_duplicates)

	logger.info(str(n) + " log files rescanned, len trails: " + str(nr_trails_unadjusted) + " (raw), " +
				str(nr_trails_incl_g3) + " (raw+guck), " +
				str(nr_trails_adjusted) + "(raw+guck, adjusted)")

	# and insert into html date
	for i, t in enumerate(trails_wo_duplicates):
		contents.insert(i_start+i, t)

	# and write to html file
	with open(indexhtml, "w") as f:
		f.writelines(contents)


def read_config(maindir, logger):

	cfg_file = maindir + "spits.cfg"
	try:
		cfg = configparser.ConfigParser()
		cfg.read(cfg_file)
		max_logs=int(cfg["OPTIONS"]["max_logs"])
		logdir = cfg["OPTIONS"]["logdir"]
		port = cfg["OPTIONS"]["port"]
		scan_interval = int(cfg["OPTIONS"]["scan_interval"])
		g3_logfile = cfg["OPTIONS"]["g3_logfile"]
	except Exception as e:
		logger.warning(str(e) + ": no config file found or config file invalid, setting to defaults!")
		max_logs = 10
		port = 8112
		logdir = "/var/log/maltrail/"
		g3_logfile = "/media/cifs/dokumente/g3logs"
		scan_interval = 120
	if not logdir.endswith("/"):
		logdir += "/"
	return max_logs, logdir, g3_logfile, port, scan_interval


def start():

	maindir = expanduser("~") + "/spits/"
	if not os.path.isdir(maindir):
		os.makedirs(maindir)

	logger = logging.getLogger("spits")
	if __version__.endswith("dev"):
		logger.setLevel(logging.DEBUG)
		llevel = "DEBUG"
	else:
		logger.setLevel(logging.INFO)
		llevel = "INFO"
	fh = logging.FileHandler(maindir + "spits.log", mode="w")
	formatter = logging.Formatter(
		"%(asctime)s - %(name)s - %(levelname)s - %(message)s"
	)
	fh.setFormatter(formatter)
	logger.addHandler(fh)
	logger.info("Welcome to SPITS " + __version__ + "!")
	logger.info("Setting Loglevel to " + llevel)
	max_logs, logdir, g3_logfile, port, scan_interval = read_config(maindir, logger)
	logger.info("max_logs: " + str(max_logs) + " / logdir: " + logdir)

	current_dir = os.path.dirname(os.path.abspath(__file__))
	indexhtmlpath = os.path.join(os.path.dirname(current_dir), "spits")
	indexhtml = os.path.join(indexhtmlpath, "index.html")

	logger.info("index_html is at: " + indexhtmlpath)

	logger.info("Starting web server on port " + str(port))

	MP = multiprocessing.Process(target=webserver_process, args=(port, indexhtmlpath, ))
	MP.daemon = True
	MP.start()

	SH = SigHandler([MP], logger)
	signal.signal(signal.SIGINT, SH.sighandler)
	signal.signal(signal.SIGTERM, SH.sighandler)

	mtime = {}
	while not SH.stopped:
		mtime, rescan = checkmtime(logdir, mtime)
		if rescan:
			scan_logs(max_logs, indexhtml, logdir, g3_logfile, logger)
		for _ in range(scan_interval * 2):
			try:
				time.sleep(0.5)
			except KeyboardInterrupt:
				break
	logger.info("Exited! (main)")
