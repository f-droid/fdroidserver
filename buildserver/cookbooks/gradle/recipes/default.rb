
user = node[:settings][:user]

script "add-gradle-dir" do
  cwd "/tmp"
  interpreter "bash"
  code "mkdir -p /opt/gradle"
  not_if "test -d /opt/gradle"
end

%w{1.4 1.6 1.7 1.8 1.9 1.10}.each do |ver|
  script "install-gradle-#{ver}" do
    cwd "/tmp"
    interpreter "bash"
    code "
      unzip /vagrant/cache/gradle-#{ver}-bin.zip
      mv gradle-#{ver} /opt/gradle/#{ver}
    "
    not_if "test -d /opt/gradle/#{ver}"
  end
end

