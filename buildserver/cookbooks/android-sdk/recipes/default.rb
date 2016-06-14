
sdk_loc = node[:settings][:sdk_loc]
user = node[:settings][:user]

script "setup-android-sdk" do
  timeout 14400
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    tools=`ls -1 /vagrant/cache/tools_*.zip | sort -n | tail -1`
    unzip $tools
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


script "add_android_packages" do
  interpreter "bash"
  user user
  code "
    #{sdk_loc}/tools/android update sdk --no-ui --all --filter platform-tools,extra-android-m2repository <<X
y

X
    "
end

script "add-platforms" do
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    rm -rf current-platform
    mkdir current-platform
    cd current-platform
    for f in `ls -1 /vagrant/cache/android-[0-9]*.zip /vagrant/cache/platform-[0-9]*.zip`; do
      unzip $f
      sdk=`sed -n 's,^ro.build.version.sdk=,,p' */build.prop`
      rm -rf #{sdk_loc}/platforms/android-$sdk
      mv * #{sdk_loc}/platforms/android-$sdk
    done
  "
end

script "add_build_tools" do
  interpreter "bash"
  user user
  cwd "/tmp"
  code "
    rm -rf current-build-tools
    mkdir current-build-tools
    cd current-build-tools
    for ver in 17 18.0.1 18.1 18.1.1 19 19.0.1 19.0.2 19.0.3 19.1 20 21 21.0.1 21.0.2 21.1 21.1.1 21.1.2 22 22.0.1 23 23.0.1 23.0.2 23.0.3; do
        unzip /vagrant/cache/build-tools_r${ver}-linux.zip
        case `echo ${ver} | wc -c` in
            3)
                dirver=${ver}.0.0
                ;;
            5)
                dirver=${ver}.0
                ;;
            7)
                dirver=${ver}
                ;;
        esac
        rm -rf #{sdk_loc}/build-tools/${dirver}
        mv android-*/ #{sdk_loc}/build-tools/${dirver}
    done
  "
end
