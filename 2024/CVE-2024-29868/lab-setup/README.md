# Lab Setup to reproduce CVE-2024-29868

I know this is unnecessary but I'll say it anyway: the following setup is only suitable as a testing environment. **Do not use it for production purposes**.

-   First, be sure to have Docker and Docker Compose installed (or Docker Desktop if you prefer).

-   Then navigate to this directory (`/lab-setup`) and run the following command: `docker compose up -d`

-   At `http://localhost` you'll find the Apache Streampipes login page while at `http://localhost:8025` the MailHog web mail dashboard will be available.

-   Login to Apache Streampipes with username: `admin@streampipes.apache.org` and password `admin`.

-   Then, select the "configuration" option on the left.
    ![select-configuration-option](/lab-setup/img/01-Select_configuration_option.png)

-   Select the "mail" option
    ![select-mail-option](/lab-setup/img/02-Select_the_mail_option.png)

-   Fill the "Mail Settings" fields with the following:
    ![mailserver-settings](/lab-setup/img/03-Mailserver_configuration.png)

-   Go back to the "general" option, put `80` in the "port" option and click "save".
    This way you'll be able to check the two options highlighted in the picture (`Allow self-registration` and `Allow self-service password recovery`).
    ![general-configuration](/lab-setup/img/04-General_configuration.png)

-   You can now follow the steps detailed in the `/exploitation` directory to try and exploit the vulnerability.
