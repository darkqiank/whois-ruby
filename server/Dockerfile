# Step 1: 指定基础镜像
FROM ruby:3.0.2

# Step 2: 设置工作目录
WORKDIR /usr/src/app

# Step 3: 复制文件
COPY . .

# Step 4: 安装依赖
RUN bundle install

# Step 5: 给start.sh执行权限
RUN chmod +x start.sh

# Step 6: 配置运行命令
CMD ["./start.sh"]
