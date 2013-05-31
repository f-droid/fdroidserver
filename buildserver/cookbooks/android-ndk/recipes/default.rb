
ndk_loc = node[:settings][:ndk_loc]

script "setup-android-ndk" do
  timeout 14400
  interpreter "bash"
  user node[:settings][:user]
  cwd "/tmp"
  code "
    if [ `uname -m` == 'x86_64' ] ; then
       SUFFIX = '_64'
    else
       SUFFIX = ''
    fi
    tar jxvf /vagrant/cache/android-ndk-r8e-linux-x86$SUFFIX.tar.bz2
    mv android-ndk-r8e #{ndk_loc}
  "
  not_if do
    File.exists?("#{ndk_loc}")
  end
end

