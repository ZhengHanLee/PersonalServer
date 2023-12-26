FROM docker.io/tgagor/centos-stream

LABEL maintainer="gback@vt.edu"

RUN yum -y install gcc openssl-devel automake libtool git diffutils make procps wget
RUN dnf -y module install nodejs:16
RUN adduser user

USER user
COPY --chown=user:user src /home/user/src
COPY --chown=user:user svelte-app /home/user/svelte-app
COPY --chown=user:user install-dependencies.sh /home/user

WORKDIR /home/user
RUN sh install-dependencies.sh
WORKDIR /home/user/src
RUN make clean
RUN make
WORKDIR /home/user/svelte-app
RUN npm install
RUN npm run build
WORKDIR /home/user/svelte-app
RUN /bin/bash get_some_mp4.sh
RUN test -d /home/user/svelte-app/build/private || mkdir /home/user/svelte-app/build/private
RUN echo 'You found the secret file' > /home/user/svelte-app/build/private/secret.txt

WORKDIR /home/user/src
CMD ./server -p 9999 -R ../svelte-app/build -a