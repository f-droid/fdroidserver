
%w{ant ant-contrib autoconf autopoint bison cmake expect libtool libssl1.0.0 libssl-dev maven openjdk-7-jdk javacc python git-core mercurial subversion bzr git-svn make perlmagick pkg-config zip ruby rubygems librmagick-ruby yasm}.each do |pkg|
  package pkg do
    action :install
  end
end

if node['kernel']['machine'] == "x86_64"
  %w{ia32-libs}.each do |pkg|
    package pkg do
      action :install
    end
  end
end

