
user = node[:settings][:user]

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

%w{1.4 1.6 1.7 1.8 1.9}.each do |ver|
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
  code %{cat << EOF > /opt/gradle/bin/gradle
#!/bin/bash

bindir=$(dirname $0)
basedir=$(dirname $bindir)
verdir="${basedir}/versions"
args=("$@")
pushd "${verdir}" &>/dev/null

v_all=(*/)
v_all=(${v_all[@]%/})

v_def=${v_all[-1]}
echo "Available gradle versions: ${v_all[@]}"

popd &>/dev/null

run_gradle() {
	${verdir}/${v_found}/bin/gradle "${args[@]}"
	exit $?
}

# key-value pairs of what gradle version each gradle plugin version
# should accept
d_plugin_k=(0.7 0.6 0.5 0.4 0.3 0.2)
d_plugin_v=(1.9 1.8 1.6 1.6 1.4 1.4)

# Latest takes priority
files=(build.gradle)

for f in ${files[@]}; do
	[[ -f $f ]] || continue
	while read l; do
		if [[ "$l" == *'com.android.tools.build:gradle:'* ]]; then
			plugin_pver=$(echo -n "$l" | sed "s/.*com.android.tools.build:gradle:\\([0-9\\.\\+]\\+\\).*/\\1/")
		elif [[ "$l" == *'gradleVersion'* ]]; then
			wrapper_ver=$(echo -n "$l" | sed "s/.*gradleVersion[ ]*=[ ]*[\"']\\([0-9\\.]\\+\\)[\"'].*/\\1/")
		fi
	done < $f
done

if [[ -n $wrapper_ver ]]; then
	v_found=$wrapper_ver
	echo "Found $v_found via gradleVersion"
	run_gradle
fi

if [[ -n $plugin_pver ]]; then
	i=0
	match=false
	for k in ${d_plugin_k[@]}; do
		if [[ $plugin_pver == ${k}* ]]; then
			plugin_ver=${d_plugin_v[$i]}
			match=true
			break
		fi
		let i++
	done
	if $match; then
		v_found=$plugin_ver
		echo "Found $v_found via gradle plugin version ${k}*"
	fi
fi

[[ -n $v_found ]] && run_gradle

echo "No suitable gradle version found - defaulting to $v_def"
v_found=$v_def
run_gradle

EOF
  }
end

execute "add-android-ndk-path" do
  user user
  command "echo \"export PATH=\\$PATH:/opt/gradle/bin #PATH-GRADLE\" >> /home/#{user}/.bsenv"
  not_if "grep PATH-GRADLE /home/#{user}/.bsenv"
end
