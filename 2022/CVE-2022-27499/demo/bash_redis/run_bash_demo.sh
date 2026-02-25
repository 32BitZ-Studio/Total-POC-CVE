#! /bin/bash
set -e

make clean
make

bomfile="../bash.yaml"

rm -rf occlum_instance
occlum new occlum_instance

pushd occlum_instance
rm -rf image
copy_bom -f $bomfile --root image --include-dir /opt/occlum/etc/template

new_json="$(jq '.resource_limits.user_space_size = "600MB" ' Occlum.json)" && \
    echo "${new_json}" > Occlum.json

cp ../load_and_encrypt_config image/bin/
## copy the Redis template config file to '/etc' in the occlum image
cp ../redis.conf.template image/etc/

occlum build

occlum run /bin/occlum_bash.sh
#OCCLUM_LOG_LEVEL=trace occlum run /bin/occlum_bash_test.sh

popd
