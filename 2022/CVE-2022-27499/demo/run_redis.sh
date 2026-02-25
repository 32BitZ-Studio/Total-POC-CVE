## Set path
path=bash_redis

postfix="_replay"
path_replay=${path}${postfix}

## build the replay enclave
echo "Building ..."
rm -rf ${path_replay}
cp -r ${path} ${path_replay}

echo "Running ..."
cd ${path}
./run_bash_demo.sh
