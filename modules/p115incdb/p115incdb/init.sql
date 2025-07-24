-- 修改日志模式为 WAL (Write Ahead Log)
PRAGMA journal_mode = WAL;

-- data 表，用来保存数据
CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,      -- 主键
    parent_id INTEGER NOT NULL DEFAULT 0, -- 上级目录的 id
    name TEXT NOT NULL,                   -- 名字
    sha1 TEXT NOT NULL DEFAULT '',        -- 文件的 sha1 散列值
    size INTEGER NOT NULL DEFAULT 0,      -- 文件大小
    pickcode TEXT NOT NULL DEFAULT '',    -- 提取码，下载等操作时需要用到
    is_dir INTEGER NOT NULL DEFAULT 0 CHECK(is_dir IN (0, 1)), -- 是否目录
    extra BLOB DEFAULT NULL,              -- 额外的数据
    is_alive INTEGER NOT NULL DEFAULT 1 CHECK(is_alive IN (0, 1)),  -- 是否存活（存活即是不是删除状态）
    created_at TIMESTAMP DEFAULT (STRFTIME('%s', 'now')), -- 创建时间
    updated_at TIMESTAMP DEFAULT (STRFTIME('%s', 'now'))  -- 更新时间
);

-- fs_event 表，用来保存文件系统变更（由 data 表触发）
CREATE TABLE IF NOT EXISTS fs_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- 事件 id
    event TEXT NOT NULL,                  -- 事件类型：add（增）、remove（删）、rename（改名）、move（移动）
    file_id INTEGER NOT NULL,             -- 文件或目录的 id，此 id 必在 `data` 表中
    pid0 INTEGER NOT NULL DEFAULT -1,     -- 变更前上级目录的 id
    pid1 INTEGER NOT NULL DEFAULT -1,     -- 变更后上级目录的 id
    name0 TEXT NOT NULL DEFAULT '',       -- 变更前的名字
    name1 TEXT NOT NULL DEFAULT '',       -- 变更后的名字
    path0 TEXT NOT NULL DEFAULT '',       -- 变更前的路径（以>作为路径分隔符）
    path1 TEXT NOT NULL DEFAULT '',       -- 变更后的路径（以>作为路径分隔符）
    is_dir INTEGER NOT NULL CHECK(is_dir IN (0, 1)),     -- 是否目录
    created_at TIMESTAMP DEFAULT (STRFTIME('%s', 'now')) -- 创建时间
);

-- life_event 表，用来保存操作事件
CREATE TABLE IF NOT EXISTS life_event (
    id INTEGER NOT NULL PRIMARY KEY, -- 文件或目录的 id
    data JSON NOT NULL, -- 数据
    created_at TIMESTAMP DEFAULT (STRFTIME('%s', 'now')) -- 创建时间
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_utime ON data(updated_at);

-- data 表的记录发生更新，自动更新它的更新时间
CREATE TRIGGER IF NOT EXISTS trg_data_update
AFTER UPDATE ON data
FOR EACH ROW
BEGIN
    UPDATE data SET updated_at = STRFTIME('%s', 'now') WHERE id = NEW.id;
END;

-- data 表发生插入
CREATE TRIGGER IF NOT EXISTS trg_data_insert
AFTER INSERT ON data
FOR EACH ROW
BEGIN
    INSERT INTO fs_event(event, file_id, pid1, name1, path1, is_dir) VALUES (
        'add', NEW.id, NEW.parent_id, NEW.name, (
            WITH ancestors(path, parent_id) AS (
                SELECT '>' || name, parent_id FROM data WHERE id = NEW.id
                UNION ALL
                SELECT ancestors.path || '>' || data.name, data.parent_id FROM ancestors JOIN data ON (ancestors.parent_id = data.id)
            )
            SELECT path FROM ancestors WHERE parent_id = 0
        ), NEW.is_dir
    );
END;

-- data 表发生移除
CREATE TRIGGER IF NOT EXISTS trg_data_remove
AFTER UPDATE ON data
FOR EACH ROW WHEN (OLD.is_alive AND NOT NEW.is_alive)
BEGIN
    INSERT INTO fs_event(event, file_id, pid0, name0, path0, is_dir) VALUES (
        'remove', OLD.id, OLD.parent_id, OLD.name, (
            WITH ancestors(path, parent_id) AS (
                SELECT '>' || name, parent_id FROM data WHERE id = OLD.id
                UNION ALL
                SELECT ancestors.path || '>' || data.name, data.parent_id FROM ancestors JOIN data ON (ancestors.parent_id = data.id)
            )
            SELECT path FROM ancestors WHERE parent_id = 0
        ), OLD.is_dir
    );
END;

-- data 表发生还原
CREATE TRIGGER IF NOT EXISTS trg_data_revoke
AFTER UPDATE ON data
FOR EACH ROW WHEN (NOT OLD.is_alive AND NEW.is_alive)
BEGIN
    INSERT INTO fs_event(event, file_id, pid1, name1, path1, is_dir) VALUES (
        'add', NEW.id, NEW.parent_id, NEW.name, (
            WITH ancestors(path, parent_id) AS (
                SELECT '>' || name, parent_id FROM data WHERE id = NEW.id
                UNION ALL
                SELECT ancestors.path || '>' || data.name, data.parent_id FROM ancestors JOIN data ON (ancestors.parent_id = data.id)
            )
            SELECT path FROM ancestors WHERE parent_id = 0
        ), NEW.is_dir
    );
END;

-- data 表发生改名或移动
CREATE TRIGGER IF NOT EXISTS trg_data_change
AFTER UPDATE ON data
FOR EACH ROW WHEN (OLD.is_alive AND NEW.is_alive)
BEGIN
    INSERT INTO fs_event(event, file_id, pid0, pid1, name0, name1, path0, path1, is_dir) 
    (
        SELECT
            'move', OLD.id, OLD.parent_id, NEW.parent_id, OLD.name, OLD.name, (
                WITH ancestors(path, parent_id) AS (
                    SELECT '>' || name, parent_id FROM data WHERE id = OLD.parent_id
                    UNION ALL
                    SELECT ancestors.path || '>' || data.name, data.parent_id FROM ancestors JOIN data ON (ancestors.parent_id = data.id)
                )
                SELECT COALESCE((SELECT path FROM ancestors WHERE parent_id = 0), '') || '>' || OLD.name
            ), (
                WITH ancestors(path, parent_id) AS (
                    SELECT '>' || name, parent_id FROM data WHERE id = NEW.parent_id
                    UNION ALL
                    SELECT ancestors.path || '>' || data.name, data.parent_id FROM ancestors JOIN data ON (ancestors.parent_id = data.id)
                )
                SELECT COALESCE((SELECT path FROM ancestors WHERE parent_id = 0), '') || '>' || OLD.name
            ), OLD.is_dir
        WHERE OLD.parent_id != NEW.parent_id
    );
    INSERT INTO fs_event(event, file_id, pid0, pid1, name0, name1, path0, path1, is_dir) 
    (
        WITH ancestors(path, parent_id) AS (
            SELECT '>' || name, parent_id FROM data WHERE id = NEW.parent_id
            UNION ALL
            SELECT ancestors.path || '>' || data.name, data.parent_id FROM ancestors JOIN data ON (ancestors.parent_id = data.id)
        )
        SELECT
            'rename', NEW.id, NEW.parent_id, NEW.parent_id, OLD.name, NEW.name, (
                SELECT COALESCE((SELECT path FROM ancestors WHERE parent_id = 0), '') || '>' || OLD.name
            ), (
                SELECT COALESCE((SELECT path FROM ancestors WHERE parent_id = 0), '') || '>' || NEW.name
            ), NEW.is_dir
        WHERE OLD.name != NEW.name
    );
END;
