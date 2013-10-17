
ndk_loc = node[:settings][:ndk_loc]
user = node[:settings][:user]

execute "add-android-ndk-path" do
  user user
  command "echo \"export PATH=\\$PATH:#{ndk_loc} #PATH-NDK\" >> /home/#{user}/.bsenv"
  not_if "grep PATH-NDK /home/#{user}/.bsenv"
end

execute "add-android-ndk-var" do
  user user
  command "echo \"export ANDROID_NDK=#{ndk_loc}\" >> /home/#{user}/.bsenv"
  not_if "grep ANDROID_NDK /home/#{user}/.bsenv"
end

script "setup-android-ndk" do
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
    tar jxvf /vagrant/cache/android-ndk-r9-linux-x86$SUFFIX.tar.bz2
    tar jxvf /vagrant/cache/android-ndk-r9-linux-x86$SUFFIX-legacy-toolchains.tar.bz2
    mv android-ndk-r9 #{ndk_loc}
  "
  not_if do
    File.exists?("#{ndk_loc}")
  end
end

