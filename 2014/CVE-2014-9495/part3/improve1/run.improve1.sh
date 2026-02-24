git clone --branch submit_improve1 --single-branch git@github.com:Enessar/oss-fuzz.git
cd oss-fuzz

sudo python3 infra/helper.py build_image libpng
sudo python3 infra/helper.py build_fuzzers libpng

# Run the fuzzer with the seed corpus
sudo mkdir build/out/read_seed
sudo timeout 4h python3 infra/helper.py run_fuzzer libpng libpng_read_fuzzer --corpus-dir build/out/read_seed