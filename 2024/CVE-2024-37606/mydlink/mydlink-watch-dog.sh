#!/bin/sh

########################
# http server checking #
########################
MAX_COUNT=5
MYDLINK_BASE="/mydlink"
PID_BASE="/tmp/run"
LOG_BASE="/tmp/md-log"

WATCHDOG_PID="$PID_BASE/mydlink-watch-dog.pid"

LOG_FILE="${LOG_BASE}/mydlink.log"
LOG_MAX_SZ=500000

DEV_CMD="mdb"
PORT_CMD="get http_port"
SPORT_CMD="get https_port"

UNIT_CHECK_T=5
HTTP_CHECK_T=300

STREAM_CGI=""
INFO_CGI="/common/info.cgi"
VIDEO_93x_CGI="/h264.cgi"
VIDEO_NIPCA_CGI="/video/ACVS-H264.cgi"
VIDEO_MJPG_CGI="/video/mjpg.cgi"

HTTP_BASE="http://127.0.0.1"
HTTPS_BASE="https://127.0.0.1"

HTTP_CMD="/mydlink/httpd_check"

# 30 days per check
CA_CHECK_PERIOD=30
CA_PID_FILE="ca-update.pid"
DST_SRV="http://ca-mgr.auto.mydlink.com/default"
PUB_KEY="public-key.pem"
CA_CHECK_FLAG="/tmp/.ca.check.flag"
TMP_CA_FILE="/tmp/.tmp.ca.file"
MD_CA_FILE="/tmp/.mydlink.ca-bundle.crt"
SYS_CA_FILE="/etc/ca-bundle.crt"
CA_FILE_NAME="ca-bundle.crt"

############################
# Message logging function #
############################
# $1: message
log() {
  #echo "[`date +"%Y-%m-%d %H:%M:%S"`] $1" >> $LOG_FILE
  echo "[`date +"%Y-%m-%d %H:%M:%S"`] $1" > /dev/null 2>&1
}

restart_httpd_93x() {
  killall -q -9 alphapd
  alphapd& > /dev/null 2>&1
}

restart_httpd_94x() {
  if [ -f "/etc/rc.d/init.d/lighttpd.sh" ]; then
    /etc/rc.d/init.d/lighttpd.sh stop
    /etc/rc.d/init.d/lighttpd.sh start
  fi
}

restart_httpd() {
  # keep the way for restart httpd after wizard setup
  if [ $DEV_CMD == "tdb" ]; then
    restart_httpd_93x
    restart_httpd_94x
  else
  # new defined way
    mdb set reload_http_service 1 > /dev/null 2>&1
    mdb apply > /dev/null 2>&1
  fi
}

##########################
# Video CGI detection    #
##########################
# $1: http port
detect_stream_cgi() {
  stream_path=""
  for path in "${VIDEO_NIPCA_CGI}" "${VIDEO_93x_CGI}" "${VIDEO_MJPG_CGI}"
  do
    code=`${HTTP_CMD} ${HTTP_BASE}:${1}${path}`
    if [ "0${code}" = "0200" ]; then
      stream_path=${path}
      break;
    fi
  done

  if [ "0$stream_path" = "0" ]; then
    return 127
  fi

  log "video CGI '${stream_path}' detected."

  echo $stream_path
}


##########################
# Device httpd checking  #
##########################
#$1: http port
#$2: https port
#$3: stream_path
health_check_httpd() {
  for url in "${HTTP_BASE}:${1}${INFO_CGI}" "${HTTPS_BASE}:${2}${INFO_CGI}" "${HTTP_BASE}:${1}${3}"
  do
    # cgi checking
    count=0
    while [ $count -lt ${MAX_COUNT} ]
    do
      code=`${HTTP_CMD} ${url}`
      #log "${url} -> ${code}"
      if [ "0${code}" != "0200" ]; then
        count=`expr $count + 1`
        sleep 3
      else
        break
      fi
    done

    # retry and failed
    if [ $count -ge ${MAX_COUNT} ]; then
      log "Failed to access ${url}, restarting system services.."
      restart_httpd

      break;
    fi
  done
}


##########################
# mydlink agent checking #
##########################
# $1: process name
# $2: launch argument
check_alive() {
  # check if the program exists or not
  if [ ! -f "$MYDLINK_BASE/$1" ]; then
    return
  fi

  # check if process exists by pid
  pid="-1"
  if [ -f "${PID_BASE}/${1}.pid" ]; then
    pid=`cat ${PID_BASE}/${1}.pid`
  fi
  if [ -d "/proc/${pid}" ]; then
    restart_cnt=0
    return
  fi

  restart_cnt=`expr $restart_cnt + 1`
  if [ "$restart_cnt" -gt 6 ]; then
    log "reboot cause device agent can't startup"
    reboot
  fi

  log "$1 is not running! ($pid)"
  # kill all remaining processes and wait a moment
  killall -q $1 2>/dev/null
  sleep 1

  # launch the process
  # $MYDLINK_BASE/$1 $2 >> "${LOG_BASE}/${1}.log" 2>&1 &
  $MYDLINK_BASE/$1 $2 > /dev/null 2>&1 &
  pid="$!"
  res="$?"

  # keep the pid
  echo $pid > "${PID_BASE}/${1}.pid"

  log " - launch $1 ($pid, $res)"
}

# $1: folder
validate_log_size() {
  count=0
  size=0
  for it in `ls -l "$1"`
  do
    count=`expr $count % 9 + 1`
    if [ `expr $count % 5` -eq 0 ]; then
      size=`expr $size + $it`
    fi
  done

  if [ $size -ge $LOG_MAX_SZ ]; then
    for file in `ls $1`
    do
      echo "[`date +"%Y-%m-%d %H:%M:%S"`] reset log" > "$1/$file"
    done
    log "Reset logs in folder '$1'"
  fi
}


##########################
# Verify CA file         #
##########################
ERR_NO_ERROR=0
ERR_NO_CHANGE=1
ERR_MDB_FAIL=2

# Touch last check time
set_checked() {
  t=`date +"%s"`
  c=`expr $t / 86400`
  echo -n $c > $CA_CHECK_FLAG
}

# Check last check time
# $1: base dir
# return 0 if need to check
need_to_check() {
  ret=0

  # try to copy from system if no such file exists
  if [ -f ${SYS_CA_FILE} ] && [ ! -f ${MD_CA_FILE} ]; then
    cp ${SYS_CA_FILE} ${MD_CA_FILE}
  fi

  # check if meta-file exists. if not, the process shall be processing
  if [ ! -f ${MD_CA_FILE} ] || [ ! -f $CA_CHECK_FLAG ]; then
    return 0
  fi

  # check last access time
  t=`date +"%s"`
  curr=`expr $t / 86400`
  last=`cat $CA_CHECK_FLAG`
  next=`expr $last + $CA_CHECK_PERIOD`
  if [ $curr -lt $next ]; then
    ret=1
  fi

  return $ret
}

# CA Refresh Process
# $1 BASE
# RET result
refresh_ca() {
  # check the executable
  if [ ! -f $1/ca-refresh ]; then
    has_ca_refresh=0
    log "$1/ca-refresh not found."
    return 127
fi

  log "refreshing ca-list"
  $1/ca-refresh "${DST_SRV}" "${MD_CA_FILE}" "${TMP_CA_FILE}" "$1/${PUB_KEY}"
ret=$?

  if [ $ret -eq $ERR_NO_ERROR ]; then
    set_checked

    # update the new ca
    cp -f ${TMP_CA_FILE} ${MD_CA_FILE}

    # try to store to system
  retry=0
    while [ $retry -lt 2 ]
  do
      retry=`expr $retry + 1`
      mdb set cainfo "${TMP_CA_FILE}"
    if [ $? -eq 0 ]; then
        return $ERR_NO_ERROR
    fi
  done

    return $ERR_MDB_FAIL

elif [ $ret -eq $ERR_NO_CHANGE ]; then
  set_checked
    return $ERR_NO_ERROR

else
    log "CA refresh failed ($ret)."
fi

  return $ret
}
#=======================================================


# Get mydlink folder
if [ -f /mydlink/signalc ]; then
  MYDLINK_BASE="/mydlink"
elif [ -f /opt/signalc ]; then
  MYDLINK_BASE="/opt"
fi

HTTP_CMD="$MYDLINK_BASE/httpd_check" 

# Set mydlink into PATH
export PATH="$MYDLINK_BASE:$PATH"

# Get model name
MODEL_NAME="Unknown"
HAS_MDB=`mdb get dev_model | grep "L" -c` 2>/dev/null
if [ "1" -eq "$HAS_MDB" ]; then
  MODEL_NAME=`mdb get dev_model`

else
  DEV_CMD="tdb"
  PORT_CMD="get HTTPServer Port_num"
  SPORT_CMD="get HTTPServer HTTPSPort_num"

  wlan=`pibinfo Wireless` 2>/dev/null
  if [ "$wlan" = "1" ]; then
    MODEL_NAME=`tdb get System ModelW_ss`
  else
    MODEL_NAME=`tdb get System Model_ss`
  fi
fi


# Get LAN interface
LAN_INT="br0"
HAS_BR0=`ifconfig | grep "br0" -c`
if [ "$HAS_BR0" -ge "1" ]; then
  LAN_INT="br0"
else
  LAN_INT="eth0"
fi


# Make neccessary folders
mkdir -p $PID_BASE
mkdir -p $LOG_BASE

# Manage the watchdog PID
wd_pid="-1"
if [ -f ${WATCHDOG_PID} ]; then
    wd_pid=`cat ${WATCHDOG_PID}`
fi
if [ -d "/proc/$wd_pid" ] && [ "0$wd_pid" -ne "0$$" ]; then
  log "Watchdog is running, exit."
  exit 255
else
  echo "$$" > "${WATCHDOG_PID}"
fi


# Check agent status
runs=0
restart_cnt=0
has_ca_refresh=1
PRIVACY_MODE=0
GET_PRIV_CMD="get privmode"

while [ 1 ]
do
  curpid=`cat ${WATCHDOG_PID}`
  if [ "0$$" -ne "0$curpid" ]; then
    log "Unexpected pid (self: $$ cur: $curpid), exit!"
    exit 255
  fi

  if [ "0$has_ca_refresh" = "01" ]; then
    # check CA list
    need_to_check $MYDLINK_BASE
    if [ $? -eq 0 ]; then
      refresh_ca $MYDLINK_BASE
    fi
  fi

  # check running status of mydlink agents
  check_alive dcp "-i $LAN_INT -m $MODEL_NAME"
  check_alive signalc

  # check if device in privacy mode
  if [ "1" -eq "$HAS_MDB" ]; then
	PRIVACY_MODE=`$DEV_CMD $GET_PRIV_CMD`
	# check format
	if [ $? -ne 0 ] || [ "1" -ne "$PRIVACY_MODE" ]; then
	  PRIVACY_MODE=0
	fi
  fi

  # if device in privacy mode, we are not going to check httpd service
  if [ "0" -eq "$PRIVACY_MODE" ]; then
	# check web services
	runs=`expr $runs + $UNIT_CHECK_T`
	if [ $runs -ge $HTTP_CHECK_T ]; then
	  http_port=`$DEV_CMD $PORT_CMD`
	  https_port=`$DEV_CMD $SPORT_CMD`

	  if [ "0$STREAM_CGI" = "0" ]; then
		STREAM_CGI=`detect_stream_cgi $http_port`
	  fi

	  health_check_httpd "$http_port" "$https_port" "$STREAM_CGI"
	  runs=0
	fi
  fi

  sleep $UNIT_CHECK_T
done

