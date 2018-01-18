# icospace

## HOW TO

1. 用你喜欢的方式安装 python 环境
2. Run `pip install -r requirements` 安装依赖
3. 复制 `.env.example` 的内容到 `.env` 文件，并配置相应内容
4. 在 Mysql 中新建一个 db `ico`（可以去`config.py`中修改或者在`.env`中通过`DEV_DATABASE_URL`指定）
5. Run `python manage.py db migrate && python manage.py db upgrade` 同步数据库
6. Run `python manage.py list_routes` 查看路由
7. Run `python manage.py runserver` 启动应用

## Dependency

- mysql
- redis