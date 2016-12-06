# This image is intended to be used with fdroidserver for the purpose
# of dynamic scanning of pre-built APKs during the fdroid build process.

# Start with ubuntu 12.04 (i386).
FROM ubuntu:14.04
MAINTAINER fdroid.dscanner <fdroid.dscanner@gmail.com>

ENV DROZER_URL https://github.com/mwrlabs/drozer/releases/download/2.3.4/drozer_2.3.4.deb
ENV DROZER_DEB drozer_2.3.4.deb

ENV AGENT_URL https://github.com/mwrlabs/drozer/releases/download/2.3.4/drozer-agent-2.3.4.apk
ENV AGENT_APK drozer-agent-2.3.4.apk

# Specially for SSH access and port redirection
ENV ROOTPASSWORD android

# Expose ADB, ADB control and VNC ports
EXPOSE 22
EXPOSE 5037
EXPOSE 5554
EXPOSE 5555
EXPOSE 5900
EXPOSE 5901

ENV DEBIAN_FRONTEND noninteractive
RUN echo "debconf shared/accepted-oracle-license-v1-1 select true" | debconf-set-selections
RUN echo "debconf shared/accepted-oracle-license-v1-1 seen true" | debconf-set-selections

# Update packages
RUN apt-get -y update

# Drozer packages
RUN apt-get install wget python2.7 python-dev python2.7-dev python-openssl python-twisted python-protobuf bash-completion -y

# First, install add-apt-repository, sshd and bzip2
RUN apt-get -y install python-software-properties bzip2 ssh net-tools

# ubuntu 14.04 needs this too
RUN apt-get -y install software-properties-common

# Add oracle-jdk7 to repositories
RUN add-apt-repository ppa:webupd8team/java

# Make sure the package repository is up to date
RUN echo "deb http://archive.ubuntu.com/ubuntu trusty main universe" > /etc/apt/sources.list

# Update apt
RUN apt-get update

# Add drozer
RUN useradd -ms /bin/bash drozer

# Install oracle-jdk7
RUN apt-get -y install oracle-java7-installer

# Install android sdk
RUN wget http://dl.google.com/android/android-sdk_r23-linux.tgz
RUN tar -xvzf android-sdk_r23-linux.tgz
RUN mv -v android-sdk-linux /usr/local/android-sdk

# Install apache ant
RUN wget http://archive.apache.org/dist/ant/binaries/apache-ant-1.8.4-bin.tar.gz
RUN tar -xvzf apache-ant-1.8.4-bin.tar.gz
RUN mv -v apache-ant-1.8.4 /usr/local/apache-ant

# Add android tools and platform tools to PATH
ENV ANDROID_HOME /usr/local/android-sdk
ENV PATH $PATH:$ANDROID_HOME/tools
ENV PATH $PATH:$ANDROID_HOME/platform-tools

# Add ant to PATH
ENV ANT_HOME /usr/local/apache-ant
ENV PATH $PATH:$ANT_HOME/bin

# Export JAVA_HOME variable
ENV JAVA_HOME /usr/lib/jvm/java-7-oracle

# Remove compressed files.
RUN cd /; rm android-sdk_r23-linux.tgz && rm apache-ant-1.8.4-bin.tar.gz

# Some preparation before update
RUN chown -R root:root /usr/local/android-sdk/

# Install latest android tools and system images
RUN echo "y" | android update sdk --filter platform-tool --no-ui --force
RUN echo "y" | android update sdk --filter platform --no-ui --force
RUN echo "y" | android update sdk --filter build-tools-22.0.1 --no-ui -a
RUN echo "y" | android update sdk --filter sys-img-x86-android-19 --no-ui -a
#RUN echo "y" | android update sdk --filter sys-img-x86-android-21 --no-ui -a
#RUN echo "y" | android update sdk --filter sys-img-x86-android-22 --no-ui -a
RUN echo "y" | android update sdk --filter sys-img-armeabi-v7a-android-19 --no-ui -a
#RUN echo "y" | android update sdk --filter sys-img-armeabi-v7a-android-21 --no-ui -a
#RUN echo "y" | android update sdk --filter sys-img-armeabi-v7a-android-22 --no-ui -a

# Update ADB
RUN echo "y" | android update adb

# Create fake keymap file
RUN mkdir /usr/local/android-sdk/tools/keymaps
RUN touch /usr/local/android-sdk/tools/keymaps/en-us

# Run sshd
RUN apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo "root:$ROOTPASSWORD" | chpasswd
RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

# Install socat
RUN apt-get install -y socat

# symlink android bins
RUN ln -sv /usr/local/android-sdk/tools/android /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/emulator /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/ddms /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/scheenshot2 /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/monkeyrunner /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/monitor /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/mksdcard /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/uiautomatorviewer /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/tools/traceview /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/platform-tools/adb /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/platform-tools/fastboot /usr/local/bin/
RUN ln -sv /usr/local/android-sdk/platform-tools/sqlite3 /usr/local/bin/

# Setup DROZER...
# https://labs.mwrinfosecurity.com/tools/drozer/

# Run as drozer user
WORKDIR /home/drozer

# Site lists the shasums, however, I'm not sure the best way to integrate the
# checks here. No real idiomatic way for Dockerfile to do that and most of
# the examples online use chained commands but we want things to *BREAK* when
# the sha doesn't match. So far, I can't seem to reliably make Docker not
# finish the image build process.

# Download the console
RUN wget -c $DROZER_URL

# Install the console
RUN dpkg -i $DROZER_DEB

# Download agent
RUN wget -c $AGENT_URL
# Keep it version agnostic for other scripts such as install_drozer.py
RUN mv -v $AGENT_APK drozer-agent.apk

# Port forwarding required by drozer
RUN echo 'adb forward tcp:31415 tcp:31415' >> /home/drozer/.bashrc

# Alias for Drozer
RUN echo "alias drozer='drozer console connect'" >> /home/drozer/.bashrc

# add extra scripting
COPY install_agent.py /home/drozer/install_agent.py
RUN chmod 755 /home/drozer/install_agent.py
COPY enable_service.py /home/drozer/enable_service.py
RUN chmod 755 /home/drozer/enable_service.py
COPY drozer.py /home/drozer/drozer.py
RUN chmod 755 /home/drozer/drozer.py

# fix ownerships
RUN chown -R drozer.drozer /home/drozer

RUN apt-get -y --force-yes install python-pkg-resources=3.3-1ubuntu1
RUN apt-get -y install python-pip python-setuptools git
RUN pip install "git+https://github.com/dtmilano/AndroidViewClient.git#egg=androidviewclient"
RUN apt-get -y install python-pexpect

# Add entrypoint
COPY entrypoint.sh /home/drozer/entrypoint.sh
RUN chmod +x /home/drozer/entrypoint.sh
ENTRYPOINT ["/home/drozer/entrypoint.sh"]
