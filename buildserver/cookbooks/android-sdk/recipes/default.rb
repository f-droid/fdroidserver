
sdk_loc = node[:settings][:sdk_loc]
user = node[:settings][:user]

script "setup-android-sdk" do
  timeout 14400
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    unzip /vagrant/cache/android-sdk-tools.zip
    mkdir #{sdk_loc}
    mkdir #{sdk_loc}/platforms
    mkdir #{sdk_loc}/build-tools
    mv tools #{sdk_loc}/
  "
  not_if "test -d #{sdk_loc}"
end

script "setup-sdk-dirs" do
  interpreter "bash"
  user user
  code "
    mkdir -p #{sdk_loc}/build-tools
  "
end

execute "add-android-sdk-path" do
  user user
  path = "#{sdk_loc}/tools:#{sdk_loc}/platform-tools"
  command "echo \"export PATH=\\$PATH:#{path} #PATH-SDK\" >> /home/#{user}/.bsenv"
  not_if "grep PATH-SDK /home/#{user}/.bsenv"
end

%w{
    platform-tools
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

%w{17.0.0 18.0.1 18.1.0 18.1.1 19.0.0 19.0.1 19.0.2 19.0.3 19.1.0
    20.0.0 21.0.0 21.0.1 21.0.2 21.1.0 21.1.1 21.1.2 22.0.0 22.0.1
    23.0.0 23.0.1 23.0.2 23.0.3
}.each do |ver|
  script "add_btools_#{ver}" do
    interpreter "bash"
    user user
    cwd "/tmp"
    code "
      unzip /vagrant/cache/build-tools-#{ver}.zip
      mv android-*/ #{sdk_loc}/build-tools/#{ver}
    "
    not_if "test -d #{sdk_loc}/build-tools/#{ver}"
  end
end
