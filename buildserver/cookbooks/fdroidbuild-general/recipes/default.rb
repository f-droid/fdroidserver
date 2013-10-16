
user = node[:settings][:user]

%w{ant ant-contrib autoconf autopoint bison cmake expect libtool libsaxonb-java libssl1.0.0 libssl-dev maven openjdk-7-jdk javacc python git-core mercurial subversion bzr git-svn make perlmagick pkg-config zip ruby rubygems librmagick-ruby yasm imagemagick gettext python-pip}.each do |pkg|
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

execute "add-filemagic" do
  user "root"
  command "pip install filemagic"
  not_if "pip list | grep filemagic"
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
  command "echo \"export GRADLE_HOME=/opt/gradle\" >> /home/#{user}/.bsenv"
  not_if "grep GRADLE_HOME /home/#{user}/.bsenv"
end
execute "add-gradle-bin" do
  user user
  command "echo \"export PATH=\\$PATH:/opt/gradle/bin\" >> /home/#{user}/.bsenv"
  not_if "grep gradle/bin /home/#{user}/.bsenv"
end
execute "add-bsenv" do
  user user
  command "echo \". ./bsenv \" >> /home/#{user}/.bashrc"
  not_if "grep bsenv /home/#{user}/.bashrc"
end


