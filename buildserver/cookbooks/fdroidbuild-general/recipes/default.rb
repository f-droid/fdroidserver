
%w{ant ant-contrib maven2 javacc python}.each do |pkg|
  package pkg do
    action :install
  end
end

