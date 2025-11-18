-- 触发器，记录 data 表 'insert'
DROP TRIGGER IF EXISTS trg_data_insert;
CREATE TRIGGER trg_data_insert
AFTER INSERT ON data
FOR EACH ROW
BEGIN
    INSERT OR IGNORE INTO dirlen(id) SELECT NEW.id WHERE NEW.is_dir;
    UPDATE dirlen SET 
        dir_count = dir_count + NEW.is_dir, 
        file_count = file_count + NOT NEW.is_dir, 
        tree_dir_count = tree_dir_count + NEW.is_dir, 
        tree_file_count = tree_file_count + NOT NEW.is_dir
    WHERE id = NEW.parent_id;
    INSERT INTO event(id, diff, fs) VALUES (
        NEW.id, 
        JSON_OBJECT(
            'id', NEW.id, 
            'parent_id', NEW.parent_id, 
            'pickcode', NEW.pickcode, 
            'sha1', NEW.sha1, 
            'name', NEW.name, 
            'size', NEW.size, 
            'is_dir', NEW.is_dir, 
            'type', NEW.type, 
            'ctime', NEW.ctime, 
            'mtime', NEW.mtime, 
            'is_collect', NEW.is_collect, 
            'is_alive', NEW.is_alive
        ), 
        JSON_OBJECT('type', 'insert', 'is_dir', NEW.is_dir, 'src_path', NULL, 'dst_path', (
            WITH ancestors AS (
                SELECT parent_id, '/' || REPLACE(name, '/', '|') AS path FROM data WHERE id=NEW.id
                UNION ALL
                SELECT data.parent_id, '/' || REPLACE(data.name, '/', '|') || ancestors.path FROM ancestors JOIN data ON (ancestors.parent_id = data.id) WHERE ancestors.parent_id
            )
            SELECT path FROM ancestors WHERE parent_id = 0
        ), 'op', JSON_ARRAY('add'))
    );
END;

-- 触发器，记录 data 表 'update'
DROP TRIGGER IF EXISTS trg_data_update;
CREATE TRIGGER trg_data_update
AFTER UPDATE ON data 
FOR EACH ROW
WHEN NOT NEW._triggered
BEGIN
    -- 更新时间
    UPDATE data SET updated_at = strftime('%Y-%m-%dT%H:%M:%f+08:00', 'now', '+8 hours'), _triggered=1 WHERE id = NEW.id;
    -- 移除文件
    UPDATE dirlen SET
        file_count = file_count - 1, 
        tree_file_count = tree_file_count - 1
    WHERE OLD.is_alive AND NOT OLD.is_dir AND NOT (NEW.is_alive AND OLD.parent_id = NEW.parent_id) AND id = OLD.parent_id;
    -- 移除目录
    UPDATE dirlen SET
        dir_count = dir_count - 1, 
        tree_dir_count = tree_dir_count - 1 - (SELECT tree_dir_count FROM dirlen WHERE id = OLD.id), 
        tree_file_count = tree_file_count - (SELECT tree_file_count FROM dirlen WHERE id = OLD.id)
    WHERE OLD.is_alive AND OLD.is_dir AND NOT (NEW.is_alive AND OLD.parent_id = NEW.parent_id) AND id = OLD.parent_id;
    -- 移入文件
    UPDATE dirlen SET
        file_count = file_count + 1, 
        tree_file_count = tree_file_count + 1
    WHERE NEW.is_alive AND NOT OLD.is_dir AND NOT (OLD.is_alive AND OLD.parent_id = NEW.parent_id) AND id = NEW.parent_id;
    -- 移入目录
    UPDATE dirlen SET
        dir_count = dir_count + 1, 
        tree_dir_count = tree_dir_count + 1 + (SELECT tree_dir_count FROM dirlen WHERE id = OLD.id), 
        tree_file_count = tree_file_count + (SELECT tree_file_count FROM dirlen WHERE id = OLD.id)
    WHERE NEW.is_alive AND OLD.is_dir AND NOT (OLD.is_alive AND OLD.parent_id = NEW.parent_id) AND id = NEW.parent_id;
    -- 更新 is_alive 标记
    UPDATE dirlen SET is_alive = NEW.is_alive WHERE id = NEW.id;
    -- 写入事件
    INSERT INTO event(id, old, diff, fs)
    SELECT *, (
        WITH t(event) AS (
            VALUES 
                (CASE WHEN diff->>'is_alive' THEN 'revert' END), 
                (CASE WHEN diff->>'is_alive' = 0 THEN 'remove' END), 
                (CASE WHEN diff->>'name' IS NOT NULL THEN 'rename' END), 
                (CASE WHEN diff->>'parent_id' IS NOT NULL THEN 'move' END)
        ), op(op) AS (
            SELECT JSON_GROUP_ARRAY(event) FROM t WHERE event IS NOT NULL
        )
        SELECT JSON_OBJECT('type', 'update', 'is_dir', NEW.is_dir, 'src_path', (
            CASE 
                WHEN OLD.parent_id = 0 THEN '/' || REPLACE(OLD.name, '/', '|') 
                ELSE (
                    WITH ancestors AS (
                        SELECT parent_id, '/' || REPLACE(name, '/', '|') AS path FROM data WHERE id=OLD.parent_id
                        UNION ALL
                        SELECT data.parent_id, '/' || REPLACE(data.name, '/', '|') || ancestors.path FROM ancestors JOIN data ON (ancestors.parent_id = data.id) WHERE ancestors.parent_id
                    )
                    SELECT path || '/' || REPLACE(OLD.name, '/', '|') FROM ancestors WHERE parent_id = 0
                ) 
            END
        ), 'dst_path', (
            CASE 
                WHEN NEW.parent_id = 0 THEN '/' || REPLACE(NEW.name, '/', '|')
                ELSE (
                    WITH ancestors AS (
                        SELECT parent_id, '/' || REPLACE(name, '/', '|') AS path FROM data WHERE id=NEW.parent_id
                        UNION ALL
                        SELECT data.parent_id, '/' || REPLACE(data.name, '/', '|') || ancestors.path FROM ancestors JOIN data ON (ancestors.parent_id = data.id) WHERE ancestors.parent_id
                    )
                    SELECT path || '/' || REPLACE(NEW.name, '/', '|') FROM ancestors WHERE parent_id = 0
                )
            END
        ), 'op', JSON(op.op)) FROM op WHERE JSON_ARRAY_LENGTH(op.op)
    )
    FROM (
        WITH data(id, old, new) AS (
            SELECT
                NEW.id, 
                JSON_OBJECT(
                    'id', OLD.id, 
                    'parent_id', OLD.parent_id, 
                    'pickcode', OLD.pickcode, 
                    'sha1', OLD.sha1, 
                    'name', OLD.name, 
                    'size', OLD.size, 
                    'is_dir', OLD.is_dir, 
                    'type', OLD.type, 
                    'ctime', OLD.ctime, 
                    'mtime', OLD.mtime, 
                    'is_collect', OLD.is_collect, 
                    'is_alive', OLD.is_alive
                ) AS old, 
                JSON_OBJECT(
                    'id', NEW.id, 
                    'parent_id', NEW.parent_id, 
                    'pickcode', NEW.pickcode, 
                    'sha1', NEW.sha1, 
                    'name', NEW.name, 
                    'size', NEW.size, 
                    'is_dir', NEW.is_dir, 
                    'type', NEW.type, 
                    'ctime', NEW.ctime, 
                    'mtime', NEW.mtime, 
                    'is_collect', NEW.is_collect, 
                    'is_alive', NEW.is_alive
                ) AS new
        ), old(key, value) AS (
            SELECT tbl.key, tbl.value FROM data, JSON_EACH(data.old) AS tbl
        ), new(key, value) AS (
            SELECT tbl.key, tbl.value FROM data, JSON_EACH(data.new) AS tbl
        ), diff(diff) AS (
            SELECT JSON_GROUP_OBJECT(key, new.value)
            FROM old JOIN new USING (key)
            WHERE old.value != new.value
        )
        SELECT data.id, data.old, diff.diff FROM data, diff WHERE data.old != data.new
    );
END;
