
sdk_loc = node[:settings][:sdk_loc]
user = node[:settings][:user]

script "setup-android-sdk" do
  timeout 14400
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    tar zxvf /vagrant/cache/android-sdk_r24.1.2-linux.tgz
    mv android-sdk-linux #{sdk_loc}
    #{sdk_loc}/tools/android update sdk --no-ui -t platform-tool
    #{sdk_loc}/tools/android update sdk --no-ui -t tool
  "
  not_if "test -d #{sdk_loc}"
end

execute "add-android-sdk-path" do
  user user
  path = "#{sdk_loc}/tools:#{sdk_loc}/platform-tools"
  command "echo \"export PATH=\\$PATH:#{path} #PATH-SDK\" >> /home/#{user}/.bsenv"
  not_if "grep PATH-SDK /home/#{user}/.bsenv"
end

script "add_build_tools" do
  interpreter "bash"
  user user
  ver = "22.0.0"
  cwd "/tmp"
  code "
    if [ -f /vagrant/cache/build-tools/#{ver}.tar.gz ] ; then
      echo Installing from cache
      mkdir #{sdk_loc}/build-tools
      tar -C #{sdk_loc}/build-tools -z -x -f /vagrant/cache/build-tools/#{ver}.tar.gz
    else
      #{sdk_loc}/tools/android update sdk --no-ui -a -t build-tools-#{ver} <<X
y

X
    fi
	sed -i '/BTPATH/d' /home/#{user}/.bsenv
	echo \"export PATH=\\$PATH:#{sdk_loc}/build-tools/#{ver} #BTPATH\" >> /home/#{user}/.bsenv
  "
  not_if "test -d #{sdk_loc}/build-tools/#{ver}"
end

script "add_platform_tools" do
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    if [ -f /vagrant/cache/platform-tools.tar.gz ] ; then
      echo Installing from cache
      mkdir #{sdk_loc}/platform-tools
      tar -C #{sdk_loc}/platform-tools -z -x -f /vagrant/cache/platform-tools.tar.gz
    else
      #{sdk_loc}/tools/android update sdk --no-ui -a -t platform-tools <<X
y

X
    fi
  "
  not_if "test -d #{sdk_loc}/platform-tools"
end

%w{android-3 android-4 android-5 android-6 android-7 android-8 android-9
   android-10 android-11 android-12 android-13 android-14 android-15
   android-16 android-17 android-18 android-19 android-20 android-21
   android-22
   extra-android-support extra-android-m2repository}.each do |sdk|

  script "add_sdk_#{sdk}" do
    interpreter "bash"
    user user
    cwd "/tmp"
    code "
      if [ -f /vagrant/cache/platforms/#{sdk}.tar.gz ] ; then
        echo Installing from cache
        tar -C #{sdk_loc}/platforms -z -x -f /vagrant/cache/platforms/#{sdk}.tar.gz
      else
        echo Installing via 'android'
        #{sdk_loc}/tools/android update sdk --no-ui -a -t #{sdk} <<X
y

X
      fi
    "
    not_if "test -d #{sdk_loc}/platforms/#{sdk}"
  end

end

