%w{openjdk-6-jdk}.each do |pkg|
  package pkg do
    action :install
  end
end

sdk_loc = node[:settings][:sdk_loc]
user = node[:settings][:user]

script "setup-android-sdk" do
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    wget http://dl.google.com/android/android-sdk_r16-linux.tgz
    tar zxvf android-sdk_r16-linux.tgz
    mv android-sdk-linux #{sdk_loc}
    rm android-sdk_r16-linux.tgz
    #{sdk_loc}/tools/android update sdk --no-ui -t platform-tool
    #{sdk_loc}/tools/android update sdk --no-ui -t tool
    #{sdk_loc}/tools/android update sdk --no-ui -t android-3
    #{sdk_loc}/tools/android update sdk --no-ui -t android-4
    #{sdk_loc}/tools/android update sdk --no-ui -t android-7
    #{sdk_loc}/tools/android update sdk --no-ui -t android-8
    #{sdk_loc}/tools/android update sdk --no-ui -t android-10
    #{sdk_loc}/tools/android update sdk --no-ui -t android-11
    #{sdk_loc}/tools/android update sdk --no-ui -t android-13
    #{sdk_loc}/tools/android update sdk --no-ui -t android-14
    #{sdk_loc}/tools/android update sdk --no-ui -t android-15
    #{sdk_loc}/tools/android update sdk --no-ui -t android-16
    #{sdk_loc}/tools/android update sdk --no-ui -t addon-google_apis-google-16
  "
  not_if do
    File.exists?("#{sdk_loc}")
  end
end

execute "add-android-sdk-path" do
  user user
  path = "#{sdk_loc}/tools:#{sdk_loc}/platform-tools"
  command "echo \"export PATH=\\$PATH:#{path}\" >> /home/#{user}/.bashrc"
  not_if "grep #{sdk_loc} /home/#{user}/.bashrc"
end

