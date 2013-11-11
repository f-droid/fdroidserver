
user = node[:settings][:user]

execute "apt-get-update" do
  command "apt-get update"
  action :nothing
end

%w{ant ant-contrib autoconf autopoint bison cmake expect libtool libsaxonb-java libssl1.0.0 libssl-dev maven openjdk-7-jdk javacc python python-magic git-core mercurial subversion bzr git-svn make perlmagick pkg-config zip ruby rubygems librmagick-ruby yasm imagemagick gettext realpath transfig}.each do |pkg|
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
    unzip /vagrant/cache/gradle-1.8-bin.zip
    mv gradle-1.8 /opt/gradle
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
  command "echo \". ./.bsenv \" >> /home/#{user}/.bashrc"
  not_if "grep bsenv /home/#{user}/.bashrc"
end


