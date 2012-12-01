
%w{ant ant-contrib autoconf bison libtool libssl libssl-dev maven javacc python git-core mercurial subversion bzr git-svn make perlmagick zip}.each do |pkg|
  package pkg do
    action :install
  end
end

