
%w{ant ant-contrib maven2 javacc python git-core mercurial subversion bzr}.each do |pkg|
  package pkg do
    action :install
  end
end

