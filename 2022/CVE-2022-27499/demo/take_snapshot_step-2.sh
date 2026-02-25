## Set path
path=bash_redis

postfix="_replay"
path_replay=${path}${postfix}

# copy __ROOT/metadata in run
echo "Copying the 'metadata' file ..."
rm -f ${path_replay}/occlum_instance/run/mount/__ROOT/metadata
cp ${path}/occlum_instance/run/mount/__ROOT/metadata ${path_replay}/occlum_instance/run/mount/__ROOT/metadata

echo "Step 2 Done."
