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
END;

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
END;
