
ndk_loc = node[:settings][:ndk_loc]
user = node[:settings][:user]

script "setup-android-ndk" do
  timeout 14400
  interpreter "bash"
  user node[:settings][:user]
  cwd "/tmp"
  code "
    mkdir -p #{ndk_loc}
  "
end

script "setup-android-ndk-r9b" do
  timeout 14400
  interpreter "bash"
  user node[:settings][:user]
  cwd "/tmp"
  code "
    if [ `uname -m` == 'x86_64' ] ; then
       SUFFIX='_64'
    else
       SUFFIX=''
    fi
    tar jxvf /vagrant/cache/android-ndk-r9b-linux-x86$SUFFIX.tar.bz2
    tar jxvf /vagrant/cache/android-ndk-r9b-linux-x86$SUFFIX-legacy-toolchains.tar.bz2
    mv android-ndk-r9b #{ndk_loc}/r9b
  "
  not_if "test -d #{ndk_loc}/r9b"
end

script "setup-android-ndk-r10e" do
  timeout 14400
  interpreter "bash"
  user node[:settings][:user]
  cwd "/tmp"
  code "
    if [ `uname -m` == 'x86_64' ] ; then
       SUFFIX='_64'
    else
       SUFFIX=''
    fi
    cd #{ndk_loc}
    7zr x /vagrant/cache/android-ndk-r10e-linux-x86$SUFFIX.bin
    mv android-ndk-r10e r10e
  "
  not_if "test -d #{ndk_loc}/r10e"
end

