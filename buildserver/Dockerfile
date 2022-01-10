
FROM debian:stretch

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

# setup 'vagrant' user for compatibility
RUN useradd --create-home -s /bin/bash vagrant && echo -n 'vagrant:vagrant' | chpasswd

RUN printf "path-exclude=/usr/share/locale/*\npath-exclude=/usr/share/man/*\npath-exclude=/usr/share/doc/*\npath-include=/usr/share/doc/*/copyright\n" >/etc/dpkg/dpkg.cfg.d/01_nodoc \
	&& mkdir -p /usr/share/man/man1 \
	&& apt-get update \
	&& apt-get upgrade \
	&& apt-get dist-upgrade \
	&& apt-get install sudo \
	&& apt-get autoremove --purge \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Vagrant sudo setup for compatibility
RUN echo 'vagrant ALL = NOPASSWD: ALL' > /etc/sudoers.d/vagrant \
	&& chmod 440 /etc/sudoers.d/vagrant \
	&& sed -i -e 's/Defaults.*requiretty/#&/' /etc/sudoers
