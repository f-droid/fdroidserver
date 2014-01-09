
user = node[:settings][:user]

execute "apt-get-update" do
  command "apt-get update"
end

%w{ant ant-contrib autoconf autopoint bison cmake expect libtool libsaxonb-java libssl1.0.0 libssl-dev maven openjdk-7-jdk javacc python python-magic git-core mercurial subversion bzr git-svn make perlmagick pkg-config zip ruby rubygems librmagick-ruby yasm imagemagick gettext realpath transfig texinfo}.each do |pkg|
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

script "add-gradle-dir" do
  cwd "/tmp"
  interpreter "bash"
  code "mkdir -p /opt/gradle"
  not_if "test -d /opt/gradle"
end

%w{1.4 1.6 1.7 1.8 1.9}.each do |ver|
  script "install-gradle-#{ver}" do
    cwd "/tmp"
    interpreter "bash"
    code "
      unzip /vagrant/cache/gradle-#{ver}-bin.zip
      mv gradle-#{ver} /opt/gradle/#{ver}
    "
    not_if "test -d /opt/gradle/#{ver}"
  end
end

execute "add-bsenv" do
  user user
  command "echo \". ./.bsenv \" >> /home/#{user}/.bashrc"
  not_if "grep bsenv /home/#{user}/.bashrc"
end


