
FROM debian:bullseye

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive

RUN echo Etc/UTC > /etc/timezone \
	&& echo 'APT::Install-Recommends "0";' \
		'APT::Install-Suggests "0";' \
		'APT::Acquire::Retries "20";' \
		'APT::Get::Assume-Yes "true";' \
		'Dpkg::Use-Pty "0";' \
		'quiet "1";' \
        >> /etc/apt/apt.conf.d/99gitlab

# provision-apt-proxy was deliberately omitted, its not relevant in Docker
COPY 	provision-android-ndk \
	provision-android-sdk \
	provision-apt-get-install \
	provision-buildserverid \
	provision-gradle \
	setup-env-vars \
	/opt/buildserver/

ARG GIT_REV_PARSE_HEAD=unspecified
LABEL org.opencontainers.image.revision=$GIT_REV_PARSE_HEAD

# setup 'vagrant' user for compatibility
RUN useradd --create-home -s /bin/bash vagrant && echo -n 'vagrant:vagrant' | chpasswd

# The provision scripts must be run in the same order as in Vagrantfile
# - vagrant needs openssh-client iproute2 ssh sudo
# - ansible needs python3
#
# Debian Docker images will soon default to HTTPS for apt sources, so force it.
# https://github.com/debuerreotype/docker-debian-artifacts/issues/15
#
# Ensure fdroidserver's dependencies are marked manual before purging
# unneeded packages, otherwise, all its dependencies get purged.
RUN printf "path-exclude=/usr/share/locale/*\npath-exclude=/usr/share/man/*\npath-exclude=/usr/share/doc/*\npath-include=/usr/share/doc/*/copyright\n" >/etc/dpkg/dpkg.cfg.d/01_nodoc \
	&& mkdir -p /usr/share/man/man1 \
	&& apt-get update \
	&& apt-get install apt-transport-https ca-certificates \
	&& sed -i 's,http:,https:,' /etc/apt/sources.list \
	&& apt-get upgrade \
	&& apt-get dist-upgrade \
	&& apt-get install openssh-client iproute2 python3 openssh-server sudo \
	&& bash /opt/buildserver/setup-env-vars /opt/android-sdk \
	&& . /etc/profile.d/bsenv.sh \
	&& bash /opt/buildserver/provision-apt-get-install https://deb.debian.org/debian \
	&& tools=tools_r25.2.5-linux.zip \
	&& mkdir -p /vagrant/cache \
	&& curl https://dl.google.com/android/repository/$tools > /vagrant/cache/$tools \
	&& echo "577516819c8b5fae680f049d39014ff1ba4af870b687cab10595783e6f22d33e /vagrant/cache/$tools" | sha256sum -c \
	&& bash /opt/buildserver/provision-android-sdk \
	&& bash /opt/buildserver/provision-android-ndk /opt/android-sdk/ndk \
	&& bash /opt/buildserver/provision-gradle \
	&& bash /opt/buildserver/provision-buildserverid $GIT_REV_PARSE_HEAD \
	&& rm -rf /vagrant/cache \
	&& apt-mark manual `apt-cache depends fdroidserver | sed -nE 's,^[| ]*Depends: ([a-z0-9 -]+),\1,p'` \
	&& apt-get autoremove --purge \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Vagrant sudo setup for compatibility
RUN echo 'vagrant ALL = NOPASSWD: ALL' > /etc/sudoers.d/vagrant \
	&& chmod 440 /etc/sudoers.d/vagrant \
	&& sed -i -e 's/Defaults.*requiretty/#&/' /etc/sudoers
