# 115 网盘基于 p115updatedb 导出数据库的挂载服务

## 安装

你可以通过 [pypi](https://pypi.org/project/p115servedb/) 安装

```console
pip install -U p115servedb
```

## 用法

### 命令行使用

#### 开启 webdav

挂载地址为 `/<dav`，无用户名和密码（或者随便瞎填一个）

```console
$ servedb dav -f 115-dbfile.db
```

或者

```console
$ servedb-dav -f 115-dbfile.db
```

#### 开启 fuse

```console
$ servedb fuse -f 115-dbfile.db
```

或者

```console
$ servedb-fuse -f 115-dbfile.db
```
