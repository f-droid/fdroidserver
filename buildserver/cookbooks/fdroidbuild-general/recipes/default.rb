
user = node[:settings][:user]
debian_mirror = node[:settings][:debian_mirror]

execute 'set_debian_mirror' do
  command "sed -i 's,http://ftp.uk.debian.org/debian/,#{debian_mirror},g' /etc/apt/sources.list"
end

execute "jessie_backports" do
  command "echo 'deb #{debian_mirror} jessie-backports main' > /etc/apt/sources.list.d/backports.list"
  only_if "grep jessie /etc/apt/sources.list"
end

if node['kernel']['machine'] == "x86_64"
  execute "archi386" do
    command "dpkg --add-architecture i386"
  end
end

execute "apt-get-update" do
  command "apt-get update"
end

%w{
    ant
    ant-contrib
    autoconf
    autoconf2.13
    automake1.11
    autopoint
    bison
    bzr
    cmake
    curl
    expect
    faketime
    flex
    gettext
    git-core
    git-svn
    gperf
    graphviz
    imagemagick
    inkscape
    javacc
    libarchive-zip-perl
    libexpat1-dev
    libglib2.0-dev
    liblzma-dev
    librsvg2-bin
    libsaxonb-java
    libssl-dev
    libssl1.0.0
    libtool
    libtool-bin
    make
    maven
  }.each do |pkg|
  package pkg do
    action :install
  end
end

%w{
    mercurial
    nasm
    openjdk-8-jdk-headless
    optipng
    p7zip
    pandoc
    perlmagick
    pkg-config
    python-gnupg
    python-magic
    python-setuptools
    python3-gnupg
    python3-requests
    python3-yaml
    qt5-default
    qtbase5-dev
    quilt
    realpath
    scons
    subversion
    swig
    texinfo
    transfig
    unzip
    vorbis-tools
    xsltproc
    yasm
    zip
  }.each do |pkg|
  package pkg do
    action :install
  end
end

if node['kernel']['machine'] == "x86_64"
  %w{libstdc++6:i386 libgcc1:i386 zlib1g:i386 libncurses5:i386}.each do |pkg|
    package pkg do
      action :install
    end
  end
end

easy_install_package "compare-locales" do
  options "-U"
  action :install
end

if node['kernel']['machine'] == "x86_64"
  execute "set-default-java" do
    command "update-java-alternatives --set java-1.8.0-openjdk-amd64"
  end
else
  execute "set-default-java" do
    command "update-java-alternatives --set java-1.8.0-openjdk-i386"
  end
end
