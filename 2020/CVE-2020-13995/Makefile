all:
	docker build -t extract75-cve-2020-13955 .

run:
	# Turn off ASLR, run, and turn back on ASLR, for vr purposes.
	#echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
	docker run -v `pwd`/lab:/mnt -it extract75-cve-2020-13955 bash
	#echo 1 | sudo tee /proc/sys/kernel/randomize_va_space
