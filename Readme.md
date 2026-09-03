Employee Register Docker 部署文档

一、项目目录

```
/app/employee_register
├── be
│   ├── app.py
│   ├── config.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── fe
│   ├── index.html
│   ├── admin_login.html
│   ├── admin_manage.html
│   ├── reset.html
│   ├── reset_confirm.html
│   ├── nginx.conf
│   └── Dockerfile
```

二、后端 Dockerfile

```
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install -r requirements.txt \
    && pip install gunicorn

COPY . .

EXPOSE 5000

CMD ["gunicorn","-b","0.0.0.0:5000","app:app"]
```

三、前端 Dockerfile

```
FROM nginx:alpine

COPY . /usr/share/nginx/html/

COPY nginx.conf /etc/nginx/conf.d/default.conf
```

四、nginx.conf

```
server {

    listen 80;

    server_name ad.wfq.com 172.168.30.202;

    root /usr/share/nginx/html;

    index index.html;

    location /api/ {

        proxy_pass http://employee-be:5000;

        proxy_set_header Host $host;

        proxy_set_header X-Real-IP $remote_addr;

    }

    location = /admin {

        try_files /admin_login.html =404;

    }

    location = /admin/manage {

        try_files /admin_manage.html =404;

    }

    location = /reset {

        try_files /reset.html =404;

    }

    location = /reset/confirm {

        try_files /reset_confirm.html =404;

    }

    location = / {

        try_files /index.html =404;

    }

}
```

五、创建 Docker 网络

```
docker network create employee-net
docker network ls
```

六、构建镜像

```
cd /app/employee_register/be

docker build -t employee-be .

cd /app/employee_register/fe

docker build -t employee-fe .
```

七、删除旧容器

```
docker rm -f employee-be employee-fe
```

八、启动后端

```
FROM python:3.11-slim

# 关闭 Python 缓存，日志直接输出
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 工作目录
WORKDIR /app

# 先复制依赖，利用 Docker 缓存
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# 复制项目
COPY . .

# 暴露端口
EXPOSE 5000

# 健康检查（假设首页能访问）
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/', timeout=3)" || exit 1

# 启动 Gunicorn
CMD ["gunicorn", \
     "-b", "0.0.0.0:5000", \
     "-w", "4", \
     "--threads", "2", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
```

九、启动前端

```
FROM nginx:alpine

# 删除默认网页
RUN rm -rf /usr/share/nginx/html/*

# 复制静态资源
COPY . /usr/share/nginx/html/

# 覆盖 nginx 配置
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
CMD wget --spider -q http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

十、查看运行状态

```
docker ps
docker logs employee-be

docker logs employee-fe
docker restart employee-be
```

```
docker run -d \
--name employee-be \
--restart unless-stopped \
--network employee-net \
-v /app/employee_register/be:/app \
employee-be

docker run -d \
--name employee-fe \
--restart unless-stopped \
--network employee-net \
-p 80:80 \
-v /app/employee_register/fe:/usr/share/nginx/html \
-v /app/employee_register/fe/nginx.conf:/etc/nginx/conf.d/default.conf \
employee-fe
```

