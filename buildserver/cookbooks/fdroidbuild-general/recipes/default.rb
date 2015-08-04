
user = node[:settings][:user]

execute "apt-get-update" do
  command "apt-get update"
end

%w{ant ant-contrib autoconf autoconf2.13 automake1.11 autopoint bison bzr cmake curl expect faketime flex gettext git-core git-svn gperf graphviz imagemagick inkscape javacc libarchive-zip-perl librsvg2-bin libsaxonb-java libssl-dev libssl1.0.0 libtool make maven mercurial nasm openjdk-7-jdk optipng pandoc perlmagick pkg-config python python-gnupg python-magic python-setuptools python3-gnupg quilt realpath scons subversion swig texinfo transfig unzip vorbis-tools xsltproc yasm zip}.each do |pkg|
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

execute "add-bsenv" do
  user user
  command "echo \". ./.bsenv \" >> /home/#{user}/.bashrc"
  not_if "grep bsenv /home/#{user}/.bashrc"
end


