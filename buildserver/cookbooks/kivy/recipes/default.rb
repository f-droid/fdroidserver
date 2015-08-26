
user = node[:settings][:user]

%w{cython python-pygame python-pip python-virtualenv python-opengl python-gst0.10 python-enchant libgl1-mesa-dev libgles2-mesa-dev}.each do |pkg|
  package pkg do
    action :install
  end
end

script "install-kivy" do
  cwd "/tmp"
  interpreter "bash"
  code "
    tar xf /vagrant/cache/Kivy-1.7.2.tar.gz
    cd Kivy-1.7.2
    python setup.py install
    cd ..
    rm -rf Kivy*
  "
  not_if "python -c 'import kivy'"
end

script "install-p4a" do
  cwd "/home/vagrant"
  interpreter "bash"
  code "
    git clone https://github.com/kivy/python-for-android
    chown -R vagrant:vagrant python-for-android
    cd python-for-android
    git checkout ca369d774e2
  "
  not_if "test -d /home/vagrant/python-for-android"
end



