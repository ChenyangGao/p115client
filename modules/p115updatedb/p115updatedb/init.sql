-- 修改日志模式为 WAL (write-ahead-log)
PRAGMA journal_mode = WAL;

-- 允许触发器递归触发
PRAGMA recursive_triggers = ON;

-- data 表，用来保存数据
CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,   -- id
    parent_id INTEGER NOT NULL,        -- 上级目录 id
    name TEXT NOT NULL,                -- 名字
    sha1 TEXT NOT NULL DEFAULT '',     -- 文件的 sha1 散列值
    size INTEGER NOT NULL DEFAULT 0,   -- 文件大小
    pickcode TEXT NOT NULL DEFAULT '', -- 提取码
    type INTEGER NOT NULL DEFAULT 0,   -- 文件类型，目录的 type 总是 0
    ctime INTEGER NOT NULL DEFAULT 0,  -- 创建时间戳，一旦设置就不会更新
    mtime INTEGER NOT NULL DEFAULT 0,  -- 更新时间戳，如果名字、备注被设置（即使值没变），或者（如果自己是目录）进出回收站或增删直接子节点或设置封面，会更新此值，但移动并不更新
    is_dir INTEGER NOT NULL CHECK(is_dir IN (0, 1)), -- 是否目录
    is_collect INTEGER NOT NULL DEFAULT 0, -- 是否已被标记为违规
    is_alive INTEGER NOT NULL DEFAULT 1 CHECK(is_alive IN (0, 1)),   -- 是否存活中（未被移除）
    extra BLOB DEFAULT NULL,           -- 额外的数据
    updated_at DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%f+08:00', 'now', '+8 hours')), -- 最近一次更新时间
    _triggered INTEGER NOT NULL DEFAULT 0 -- 是否执行过触发器
);

-- life 表，用来收集 115 生活事件
CREATE TABLE IF NOT EXISTS life (
    id INTEGER NOT NULL PRIMARY KEY, -- 事件 id
    data JSON NOT NULL,              -- 事件日志数据
    create_time INTEGER NOT NULL     -- 事件时间
);

-- event 表，用于记录 data 表上发生的变更事件
CREATE TABLE IF NOT EXISTS event (
    _id INTEGER PRIMARY KEY AUTOINCREMENT, -- 主键
    id INTEGER NOT NULL,   -- 文件或目录的 id
    old JSON DEFAULT NULL, -- 更新前的值
    diff JSON NOT NULL,    -- 将更新的值
    fs JSON DEFAULT NULL,  -- 发生的文件系统事件：add:新增，remove:移除，revert:还原，move:移动，rename:重名
    created_at DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%f+08:00', 'now', '+8 hours')) -- 创建时间
);

-- dirlen 表，用于记录 data 表中每个目录的节点数
CREATE TABLE IF NOT EXISTS dirlen (
    id INTEGER NOT NULL PRIMARY KEY,            -- 目录 id
    dir_count INTEGER NOT NULL DEFAULT 0,       -- 直属目录数
    file_count INTEGER NOT NULL DEFAULT 0,      -- 直属文件数
    tree_dir_count INTEGER NOT NULL DEFAULT 0,  -- 子目录树目录数
    tree_file_count INTEGER NOT NULL DEFAULT 0, -- 子目录树文件数
    is_alive INTEGER NOT NULL DEFAULT 1 CHECK(is_alive IN (0, 1)) -- 是否存活中（未被移除）
);

-- dirlen 表插入根节点
INSERT OR IGNORE INTO dirlen(id) VALUES (0);

-- 触发器，用来更新 dirlen 表
CREATE TRIGGER IF NOT EXISTS trg_dirlen_update
AFTER UPDATE ON dirlen 
FOR EACH ROW 
WHEN OLD.id AND OLD.is_alive AND (OLD.tree_dir_count != NEW.tree_dir_count OR OLD.tree_file_count != NEW.tree_file_count)
BEGIN
    UPDATE dirlen SET
        tree_dir_count = tree_dir_count + NEW.tree_dir_count - OLD.tree_dir_count, 
        tree_file_count = tree_file_count + NEW.tree_file_count - OLD.tree_file_count
    WHERE
        id = (SELECT parent_id FROM data WHERE id = OLD.id);
END;

-- 触发器，用来丢弃 mtime 较早的更新
CREATE TRIGGER IF NOT EXISTS trg_data_before_update
BEFORE UPDATE ON data
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN NEW.mtime < OLD.mtime THEN RAISE(IGNORE)
    END;
END;

-- 索引
CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_pc ON data(pickcode);
CREATE INDEX IF NOT EXISTS idx_data_sha1 ON data(sha1);
CREATE INDEX IF NOT EXISTS idx_data_name ON data(name);
CREATE INDEX IF NOT EXISTS idx_data_utime ON data(updated_at);
CREATE INDEX IF NOT EXISTS idx_life_create ON life(create_time);
CREATE INDEX IF NOT EXISTS idx_event_create ON event(created_at);
