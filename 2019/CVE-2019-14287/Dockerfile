FROM ubuntu:18.04

RUN useradd bob && useradd alice

RUN set -ex \
  && DEBIAN_FRONTEND=noninteractive apt-get update \ 
  && apt-get upgrade -y \
  && apt-get install sudo=1.8.21p2-3ubuntu1

RUN echo 'alice ALL=(ALL,!root) NOPASSWD: ALL' >> /etc/sudoers

ADD readme.md /readme.md
ADD run.sh /run.sh
RUN chmod a+x /run.sh

USER alice
CMD ["/run.sh"]
