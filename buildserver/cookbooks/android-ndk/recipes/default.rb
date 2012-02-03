
ndk_loc = node[:settings][:ndk_loc]

script "setup-android-ndk" do
  interpreter "bash"
  user node[:settings][:user]
  cwd "/tmp"
  code "
    wget http://dl.google.com/android/ndk/android-ndk-r7-linux-x86.tar.bz2
    tar jxvf android-ndk-r7-linux-x86.tar.bz2
    mv android-ndk-r7 #{ndk_loc}
  "
  not_if do
    File.exists?("#{ndk_loc}")
  end
end

