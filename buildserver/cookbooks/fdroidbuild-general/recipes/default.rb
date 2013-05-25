
script "temp-proposed" do
  interpreter "bash"
  user node[:settings][:user]
  cwd "/tmp"
  code "
    sudo su -c 'echo deb http://archive.ubuntu.com/ubuntu/ raring-proposed restricted main multiverse universe >/etc/apt/sources.list.d/tmp.list'
    sudo apt-get update
  "
  not_if do
    File.exists?("/etc/apt/sources.list.d/tmp.list")
  end
end

%w{ant ant-contrib autoconf autopoint bison cmake expect libtool libssl1.0.0 libssl-dev maven javacc python git-core mercurial subversion bzr git-svn make perlmagick pkg-config zip ruby rubygems librmagick-ruby}.each do |pkg|
  package pkg do
    action :install
  end
end

