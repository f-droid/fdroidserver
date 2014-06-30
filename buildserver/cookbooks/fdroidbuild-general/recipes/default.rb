
user = node[:settings][:user]

execute "apt-get-update" do
  command "apt-get update"
end

%w{ant ant-contrib autoconf autopoint bison cmake expect libtool libsaxonb-java libssl1.0.0 libssl-dev maven openjdk-7-jdk javacc python python-magic git-core mercurial subversion bzr git-svn make perlmagick pkg-config zip yasm imagemagick gettext realpath transfig texinfo curl librsvg2-bin xsltproc vorbis-tools swig quilt faketime optipng}.each do |pkg|
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

execute "add-bsenv" do
  user user
  command "echo \". ./.bsenv \" >> /home/#{user}/.bashrc"
  not_if "grep bsenv /home/#{user}/.bashrc"
end


