FROM ubuntu:16.04
MAINTAINER bjozsa@att.com

ENV USER=oslo

ARG OS_VERSION="stable/newton"
ARG OS_PROJECT="keystone"
ARG OS_GITREPO=https://git.openstack.org/openstack/${OS_PROJECT}

RUN apt-get update && apt-get upgrade -y 
RUN apt-get install -y python-pip build-essential libssl-dev libffi-dev libpq-dev libldap2-dev libsasl2-dev python-dev git virtualenv

RUN pip install oslo.config tox

RUN useradd -ms /bin/bash $USER
USER $USER
WORKDIR /home/$USER

RUN git clone -b $OS_VERSION $OS_GITREPO

RUN git clone https://github.com/alanmeadows/gen-oslo-openstack-helm.git

RUN virtualenv /home/$USER/oslo-config && \
    . /home/$USER/oslo-config/bin/activate

WORKDIR /home/$USER/$OS_PROJECT

RUN pip install .
RUN tox -egenconfig

WORKDIR /home/$USER

ENTRYPOINT ["/home/$USER/oslo-config/bin/python gen-oslo-openstack-helm/generate.py"]

CMD ["-h"]
