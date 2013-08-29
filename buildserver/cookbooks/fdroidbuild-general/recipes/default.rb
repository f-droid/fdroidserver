
user = node[:settings][:user]

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

script "install-gradle" do
  cwd "/tmp"
  interpreter "bash"
  code "
    unzip /vagrant/cache/gradle-1.7-bin.zip
    mv gradle-1.7 /opt/gradle
  "
  not_if "test -d /opt/gradle"
end

execute "add-gradle-home" do
  user user
  command "echo \"export GRADLE_HOME=/opt/gradle\" >> /home/#{user}/.bashrc"
  not_if "grep GRADLE_HOME /home/#{user}/.bashrc"
end
execute "add-gradle-bin" do
  user user
  command "echo \"export PATH=\\$PATH:/opt/gradle/bin\" >> /home/#{user}/.bashrc"
  not_if "grep gradle/bin /home/#{user}/.bashrc"
end


