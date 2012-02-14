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
    #{sdk_loc}/tools/android update sdk --no-ui -t platform
    #{sdk_loc}/tools/android update sdk --no-ui -t tool,platform-tool
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

