
user = node[:settings][:user]

gradle_script = IO.read(File.join(
	File.expand_path(File.dirname(__FILE__)), "gradle"))

script "add-gradle-bindir" do
  cwd "/tmp"
  interpreter "bash"
  code "mkdir -p /opt/gradle/bin"
  not_if "test -d /opt/gradle/bin"
end

script "add-gradle-verdir" do
  cwd "/tmp"
  interpreter "bash"
  code "mkdir -p /opt/gradle/versions"
  not_if "test -d /opt/gradle/versions"
end

%w{1.4 1.6 1.7 1.8 1.9 1.10 1.11 1.12 2.1 2.2.1 2.3 2.4 2.5 2.6 2.7}.each do |ver|
  script "install-gradle-#{ver}" do
    cwd "/tmp"
    interpreter "bash"
    code "
      unzip /vagrant/cache/gradle-#{ver}-bin.zip
      mv gradle-#{ver} /opt/gradle/versions/#{ver}
    "
    not_if "test -d /opt/gradle/versions/#{ver}"
  end
end

script "add-gradle-wrapper" do
  cwd "/tmp"
  interpreter "bash"
  code "
    cat << \"EOF\" > /opt/gradle/bin/gradle
#{gradle_script}
EOF
    chmod a+x /opt/gradle/bin/gradle
  "
end

execute "add-android-ndk-path" do
  user user
  command "echo \"export PATH=\\$PATH:/opt/gradle/bin #PATH-GRADLE\" >> /home/#{user}/.bsenv"
  not_if "grep PATH-GRADLE /home/#{user}/.bsenv"
end
