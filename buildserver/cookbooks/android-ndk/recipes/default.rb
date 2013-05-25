
ndk_loc = node[:settings][:ndk_loc]

script "setup-android-ndk" do
  timeout 14400
  interpreter "bash"
  user node[:settings][:user]
  cwd "/tmp"
  code "
    tar jxvf /vagrant/cache/android-ndk-r8e-linux-x64.tar.bz2
    mv android-ndk-r8e #{ndk_loc}
  "
  not_if do
    File.exists?("#{ndk_loc}")
  end
end

