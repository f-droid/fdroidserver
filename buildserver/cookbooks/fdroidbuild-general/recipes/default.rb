
%w{ant ant-contrib autoconf autopoint bison cmake expect libtool libssl1.0.0 libssl-dev maven openjdk-7-jdk javacc python git-core mercurial subversion bzr git-svn make perlmagick pkg-config zip ruby rubygems librmagick-ruby yasm imagemagick}.each do |pkg|
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

