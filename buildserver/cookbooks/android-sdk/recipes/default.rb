
sdk_loc = node[:settings][:sdk_loc]
user = node[:settings][:user]

script "setup-android-sdk" do
  timeout 14400
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    tar zxvf /vagrant/cache/android-sdk_r22.2.1-linux.tgz
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

execute "add-android-home" do
  user user
  command "echo \"export ANDROID_HOME=#{sdk_loc}\" >> /home/#{user}/.bsenv"
  not_if "grep ANDROID_HOME /home/#{user}/.bsenv"
end

%w{18.1.1}.each do |ver|

  script "add_build_tools_#{ver}" do
    interpreter "bash"
    user user
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
    "
    not_if "test -d #{sdk_loc}/build-tools/#{ver}"
  end
end

%w{android-3 android-4 android-7 android-8 android-10 android-11
   android-12 android-13 android-14 android-15 android-16 android-17 android-18
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

%w{addon-google_apis-google-7 addon-google_apis-google-10 addon-google_apis-google-15 addon-google_apis-google-16 addon-google_apis-google-17}.each do |sdk|

  script "add_addon_#{sdk}" do
    interpreter "bash"
    user user
    cwd "/tmp"
    code "
      if [ -f /vagrant/cache/add-ons/#{sdk}.tar.gz ] ; then
        echo Installing from cache
        tar -C #{sdk_loc}/add-ons -z -x -f /vagrant/cache/add-ons/#{sdk}.tar.gz
      else
        echo Installing via 'android'
        #{sdk_loc}/tools/android update sdk --no-ui -a -t #{sdk} <<X
y

X
      fi
    "

    not_if "test -d #{sdk_loc}/add-ons/#{sdk}"

  end

end


