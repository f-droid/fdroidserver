
sdk_loc = node[:settings][:sdk_loc]
user = node[:settings][:user]

script "setup-android-sdk" do
  timeout 14400
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    tar zxvf /vagrant/cache/android-sdk_r24.4.1-linux.tgz
    mv android-sdk-linux #{sdk_loc}
  "
  not_if "test -d #{sdk_loc}"
end

execute "add-android-sdk-path" do
  user user
  path = "#{sdk_loc}/tools:#{sdk_loc}/platform-tools"
  command "echo \"export PATH=\\$PATH:#{path} #PATH-SDK\" >> /home/#{user}/.bsenv"
  not_if "grep PATH-SDK /home/#{user}/.bsenv"
end

%w{
    tools
    platform-tools
    build-tools-17.0.0
    build-tools-18.0.1
    build-tools-18.1.0
    build-tools-18.1.1
    build-tools-19.0.0
    build-tools-19.0.1
    build-tools-19.0.2
    build-tools-19.0.3
    build-tools-19.1.0
    build-tools-20.0.0
    build-tools-21.0.0
    build-tools-21.0.1
    build-tools-21.0.2
    build-tools-21.1.0
    build-tools-21.1.1
    build-tools-21.1.2
    build-tools-22.0.0
    build-tools-22.0.1
    build-tools-23.0.0
    build-tools-23.0.1
    build-tools-23.0.2
    extra-android-support
    extra-android-m2repository
}.each do |pkg|
  script "add_pkg_#{pkg}" do
    interpreter "bash"
    user user
    code "
      #{sdk_loc}/tools/android update sdk --no-ui -a -t #{pkg} <<X
y

X
    "
  end

end

%w{3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23}.each do |api|
  script "add_sdk_#{api}" do
    interpreter "bash"
    user user
    cwd "/tmp"
    code "
      unzip /vagrant/cache/android-platform-#{api}.zip
      mv android-*/ #{sdk_loc}/platforms/android-#{api}
    "
    not_if "test -d #{sdk_loc}/platforms/android-#{api}"
  end
end

