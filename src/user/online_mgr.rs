use rusqlite::{params, Connection, OpenFlags, Result, ToSql};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dids::key_mgr::SystemKeys;

const MAX_VARIABLE_NUMBER: usize = 999;
const USER_EXPIRY_THRESHOLD: u64 = 24 * 3600;
const INST_EXPIRY_THRESHOLD: u64 = 1 * 3600;
const MESSAGE_EXPIRY_THRESHOLD: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Default)]
pub struct DomainState {
    pub nodes_num: usize,
    pub users_num: usize,
    pub nodes_list: Vec<String>,
    pub node_insts: HashMap<String, Vec<String>>,
    pub inst_services: HashMap<String, Vec<String>>,
}


pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时间回拨")
        .as_secs()
}

pub fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时间回拨")
        .as_millis() as u64
}

#[derive(Debug, Clone)]
pub struct OnlineMgr {
    region: String,
    conn: Arc<Mutex<Connection>>,
    pub users: Arc<OnlineUsers>,
    pub insts: Arc<OnlineNodeInsts>,
    pub domain: Arc<std::sync::RwLock<DomainState>>,
    pub messages: Arc<OnlineMessages>,
}

impl OnlineMgr {
    pub fn new(region: &str) -> Self {
        let db_path = SystemKeys::get_path_in_sys_key_dir("online.db");

        // 共享连接
        // 🛡️ IMPORTANT: This connection is shared across threads and processes.
        // - Use SQLITE_OPEN_NO_MUTEX because we wrap it in a Mutex.
        // - Enable SERIALIZED mode to allow safe concurrent access from multiple threads.
        // - WAL mode enables high-concurrency reads without blocking writes.
        let common_conn = match Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX, // 👈 必须加！避免 SQLite 自己加锁
        ) {
            Ok(conn) => {
                conn.execute("PRAGMA journal_mode = WAL;", []);
                conn.execute("PRAGMA synchronous = NORMAL;", []);
                conn.execute("PRAGMA cache_size = 10000;", []);
                conn.execute("PRAGMA foreign_keys = ON;", []);
                conn.execute("PRAGMA temp_store = MEMORY;", []);
                conn.execute("PRAGMA busy_timeout = 5000;", []);
                conn.execute("PRAGMA wal_autocheckpoint = 1000;", []);
                Arc::new(Mutex::new(conn))
            }
            Err(e) => {
                eprintln!("[OnlineMgr] 写连接初始化失败: {}", e);
                panic!("无法打开数据库写连接");
            }
        };
        // 用户最大心跳时间
        let user_time_period = 30;
        // 实例最大心跳时间
        let inst_time_period = 30;
        // 消息清理周期时间
        let message_time_period = 60;

        let users = Arc::new(OnlineUsers::new(common_conn.clone(), user_time_period));
        let insts = Arc::new(OnlineNodeInsts::new(common_conn.clone(), inst_time_period));
        let messages = Arc::new(OnlineMessages::new(common_conn.clone(), message_time_period));

        let instance = OnlineMgr {
            region: region.to_string(),
            conn: common_conn,
            users,
            insts,
            domain: Arc::new(std::sync::RwLock::new(DomainState::default())),
            messages,
        };

        // 初始化数据库（仅首次有效）
        if let Err(e) = instance.init_db() {
            eprintln!("[OnlineUsers] 数据库初始化失败: {}", e);
        }

        instance
    }

    fn init_db(&self) -> Result<()> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[OnlineUsers] 获取写连接失败（被其他线程锁定？）");
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };

        // 元数据表（控制初始化）
        conn.execute(
            "CREATE TABLE IF NOT EXISTS __schema (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );",
            [],
        )?;

        // 尝试插入初始化标记
        let now = current_timestamp() as i64;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO __schema (key, value, created_at)
             VALUES ('database_initialized', '1', ?1);",
            [now],
        )? > 0;

        if inserted {
            // 首次初始化业务表
            conn.execute(
                "CREATE TABLE IF NOT EXISTS online_users (
                    user_id TEXT PRIMARY KEY,
                    registered_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                );",
                [],
            )?;
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_last_seen_registered_at ON online_users(last_seen, registered_at);",
                [],
            )?;

            // ✅ 新增：创建节点实例表
            conn.execute(
                "CREATE TABLE IF NOT EXISTS online_insts (
                    inst_id TEXT PRIMARY KEY,
                    registered_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    capacity INTEGER NOT NULL,
                    load INTEGER NOT NULL,       
                    services TEXT NOT NULL      -- JSON 格式的数组，如 [\"web\",\"api\"]
                );",
                [],
            )?;
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inst_last_seen ON online_insts(last_seen);",
                [],
            )?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS online_messages (
                    user_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,   
                    message TEXT NOT NULL,
                    PRIMARY KEY (user_id, timestamp)
                );",    
                [],
            )?;
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_user_time ON online_messages(user_id, timestamp);",
                [],
            )?;

            println!("[OnlineUsers] 数据库结构已创建.");
        }

        Ok(())
    }

    /// 获取节点统计信息
    pub fn get_nodes_users(&self) -> (usize, usize) {
        let domain = self.domain.read().unwrap();
        (domain.nodes_num, domain.users_num)
    }

    /// 获取节点 Top 列表
    pub fn get_nodes_top_list(&self) -> String {
        let domain = self.domain.read().unwrap();
        domain.nodes_list.join("|")
    }

    /// 设置节点统计信息
    pub fn set_nodes_users(&self, nodes: usize, users: usize, top_list: String) {
        let mut domain = self.domain.write().unwrap();
        domain.nodes_num = nodes;
        domain.users_num = users;
        if !top_list.is_empty() {
            domain.nodes_list = top_list
                .split('|')
                .map(|id| id.trim().to_string())
                .collect();
        }
    }
}

#[derive(Debug, Clone)]
pub struct OnlineUsers {
    time_period: u64,
    last_cleanup_time: Arc<AtomicU64>,
    conn: Arc<Mutex<Connection>>,
}

impl OnlineUsers {
    pub fn new(conn: Arc<Mutex<Connection>>, time_period: u64) -> Self {
        let last_cleanup_time = Arc::new(AtomicU64::new(0));

        OnlineUsers {
            conn,
            time_period,
            last_cleanup_time,
        }
    }

    /// 登记在线用户（幂等）
    pub fn log_register(&self, user_id: String) {
        let now = current_timestamp();
        let now_i64 = now as i64;
        let last_cleanup = self.last_cleanup_time.load(Ordering::Relaxed);
        let should_cleanup = now > last_cleanup + self.time_period;

        let mut conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register] 获取写连接失败（被其他线程锁定？）");
                return;
            }
        };

        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[log_register] 事务开启失败: {}", e);
                return;
            }
        };

        // ✅ 智能清理：仅在需要时执行
        if should_cleanup {
            let expiry_threshold = (now - USER_EXPIRY_THRESHOLD) as i64;
            if let Err(e) = tx.execute(
                "DELETE FROM online_users WHERE last_seen < ?1;",
                [expiry_threshold],
            ) {
                eprintln!("[log_register] 清理过期用户失败: {}", e);
            } else {
                // ✅ 清理成功，更新 last_cleanup_time
                self.last_cleanup_time.store(now, Ordering::Relaxed);
            }
        }

        // 插入或更新用户
        let _ = tx.execute(
            "INSERT INTO online_users (user_id, registered_at, last_seen)
                VALUES (?1, ?2, ?2)
                ON CONFLICT(user_id)
                DO UPDATE SET last_seen = excluded.last_seen;",
            params![user_id, now_i64],
        );

        if let Err(e) = tx.commit() {
            eprintln!("[log_register] 事务提交失败: {}", e);
        }
    }

    /// 记录访问（必须是已登记在线用户）
    pub fn log_access(&self, user_id: String) -> bool {
        let now = current_timestamp();
        let now_i64 = now as i64;
        let cutoff = (now - self.time_period) as i64; // 在线判断阈值

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register] 获取写连接失败（被其他线程锁定？）");
                return false;
            }
        };

        // 尝试更新：仅当用户在线（last_seen >= cutoff）时才更新
        let changes = match conn.execute(
            "UPDATE online_users SET last_seen = ?1 WHERE user_id = ?2 AND last_seen >= ?3;",
            params![now_i64, user_id, cutoff],
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[log_access] 数据库更新失败: {}", e);
                return false;
            }
        };

        changes > 0
    }

    /// 批量登记访问
    pub fn log_register_batch(&self, batch_ids: String) {
        let now = current_timestamp();
        let now_i64 = now as i64;
        let last_cleanup = self.last_cleanup_time.load(Ordering::Relaxed);
        let should_cleanup = now > last_cleanup + self.time_period;

        let mut conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register] 获取写连接失败（被其他线程锁定？）");
                return;
            }
        };

        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[log_register] 事务开启失败: {}", e);
                return;
            }
        };

        // ✅ 智能清理：仅在需要时执行
        if should_cleanup {
            if self
                .last_cleanup_time
                .compare_exchange(last_cleanup, now, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                let expiry_threshold = (now - USER_EXPIRY_THRESHOLD) as i64;
                if let Err(e) = tx.execute(
                    "DELETE FROM online_users WHERE last_seen < ?1;",
                    [expiry_threshold],
                ) {
                    eprintln!("[log_register] 清理过期用户失败: {}", e);
                } else {
                    // ✅ 清理成功，更新 last_cleanup_time
                    self.last_cleanup_time.store(now, Ordering::Relaxed);
                }
            }
        }

        // Step 1: 解析并收集所有非空 ID
        let ids: Vec<String> = batch_ids
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if ids.is_empty() {
            if let Err(e) = tx.commit() {
                eprintln!("[log_register_batch] 事务提交失败: {}", e);
            }
            return;
        }

        // Step 2: 分批处理，避免 SQLite 参数限制（默认 999）
        const SQLITE_MAX_VARS_PER_ROW: usize = MAX_VARIABLE_NUMBER / 3; // 每行3个参数 (user_id, reg, seen)
        const BATCH_SIZE: usize = SQLITE_MAX_VARS_PER_ROW;

        for chunk in ids.chunks(BATCH_SIZE) {
            // Step 3: 构建 (?, ?, ?) 占位符组
            let placeholders: Vec<String> =
                (0..chunk.len()).map(|_| "(?, ?, ?)".to_string()).collect();
            let placeholders_str = placeholders.join(",");

            // Step 4: 构建完整 SQL
            let sql = format!(
                "INSERT INTO online_users (user_id, registered_at, last_seen)
                    VALUES {}
                    ON CONFLICT(user_id)
                    DO UPDATE SET last_seen = excluded.last_seen;",
                placeholders_str
            );

            // Step 5: 收集所有参数：每个 ID 对应 (id, now, now)
            let mut params: Vec<&dyn ToSql> = Vec::with_capacity(chunk.len() * 3);
            for id in chunk {
                params.push(id);
                params.push(&now_i64);
                params.push(&now_i64);
            }

            // Step 6: 执行批量插入/更新
            if let Err(e) = tx.execute(&sql, params.as_slice()) {
                eprintln!("[log_register_batch] 批量插入失败: {}", e);
                // 可选择继续或 break，这里选择继续处理其他批次
            }
        }

        // Step 7: 提交事务
        if let Err(e) = tx.commit() {
            eprintln!("[log_register_batch] 事务提交失败: {}", e);
        }
    }

    pub fn log_access_batch(&self, batch_ids: String) -> usize {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;

        let mut conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register] 获取写连接失败（被其他线程锁定？）");
                return 0;
            }
        };

        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[log_access_batch] 事务开启失败: {}", e);
                return 0;
            }
        };

        let ids: Vec<String> = batch_ids
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if ids.is_empty() {
            let _ = tx.commit();
            return 0;
        }

        const SQLITE_MAX_VARS: usize = MAX_VARIABLE_NUMBER; // SQLite 默认限制
        let mut total_changes = 0;

        for chunk in ids.chunks(SQLITE_MAX_VARS) {
            let placeholders: Vec<String> = (0..chunk.len()).map(|_| "?".to_string()).collect();
            let placeholders_str = placeholders.join(",");

            let sql = format!(
                "UPDATE online_users SET last_seen = ? WHERE user_id IN ({}) AND last_seen >= ?",
                placeholders_str
            );

            let mut params: Vec<&dyn ToSql> = Vec::with_capacity(chunk.len() + 1);
            for id in chunk {
                params.push(id); // ✅ 自动转换，无 panic，无编译错误，全版本支持
            }
            params.push(&cutoff);

            match tx.execute(&sql, params.as_slice()) {
                Ok(c) => total_changes += c,
                Err(e) => eprintln!("[log_access_batch] 批量更新失败: {}", e),
            }
        }

        if let Err(e) = tx.commit() {
            eprintln!("[log_access_batch] 事务提交失败: {}", e);
        }

        total_changes
    }

    /// 获取当前活跃用户数（在 time_period 内有活动）
    pub fn get_number(&self) -> usize {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register] 获取读连接失败（被其他线程锁定？）");
                return 0;
            }
        };

        match conn.query_row(
            "SELECT COUNT(*) FROM online_users WHERE last_seen >= ?1;",
            [cutoff],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(count) => return count as usize,
            Err(e) => {
                eprintln!("查询用户数量失败: {}", e);
                return 0;
            }
        }
    }

    /// 获取最多 n 个活跃用户 ID（以 '|' 分隔）
    pub fn get_list(&self, n: usize) -> String {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;
        let limit = (n as i64).min(10000); // 防止过大

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register] 获取读连接失败（被其他线程锁定？）");
                return "".to_string();
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT user_id FROM online_users
                 WHERE last_seen >= ?1
                 ORDER BY registered_at
                 LIMIT ?2;",
        ) {
            Ok(s) => s,
            Err(_) => return "".to_string(),
        };

        let user_iter = match stmt.query_map([cutoff, limit], |row| row.get::<_, String>(0)) {
            Ok(iter) => iter,
            Err(_) => return "".to_string(),
        };

        let mut users = Vec::new();
        for user in user_iter.flatten().take(n) {
            users.push(user);
        }
        return users.join("|");
    }

    /// 判断用户是否在线（在 time_period 内活跃）
    pub fn is_online(&self, user_id: &str) -> bool {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register] 获取读连接失败（被其他线程锁定？）");
                return false;
            }
        };

        match conn.query_row(
            "SELECT 1 FROM online_users WHERE user_id = ?1 AND last_seen >= ?2;",
            params![user_id, cutoff],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(_) => return true,
            Err(rusqlite::Error::QueryReturnedNoRows) => return false,
            Err(e) => {
                eprintln!("检查在线状态失败: {}", e);
                return false;
            }
        }
    }

    /// 获取所有活跃用户列表
    pub fn get_full_list(&self) -> String {
        self.get_list(10000)
    }
}

#[derive(Debug, Clone)]
pub struct OnlineNodeInsts {
    conn: Arc<Mutex<Connection>>,
    time_period: u64,                  // ✅ 节点独立的时间窗口（如 30 秒）
    last_cleanup_time: Arc<AtomicU64>, // 共享原子时间戳（用于清理）
}


impl OnlineNodeInsts {
    pub fn new(conn: Arc<Mutex<Connection>>, time_period: u64) -> Self {
        let last_cleanup_time = Arc::new(AtomicU64::new(0));

        Self {
            conn,
            time_period,
            last_cleanup_time,
        }
    }

    /// 注册一个节点进程（首次上线）
    pub fn log_register(
        &self,
        inst_id: &str,
        capacity: u64,
        load: u64,
        services: &str,
    ) {
        let service_list: Vec<String> = services.split('|').map(|s| s.to_string()).collect();
        let now = current_timestamp();
        let now_i64 = now as i64;
        let last_cleanup = self.last_cleanup_time.load(Ordering::Relaxed);
        let should_cleanup = now > last_cleanup + self.time_period;

        let mut conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_register_node_inst] 获取写连接失败");
                return;
            }
        };

        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[log_register_node_inst] 事务开启失败: {}", e);
                return;
            }
        };

        // 智能清理：30天未活跃节点（固定策略，不依赖 time_period）
        if should_cleanup {
            let expiry_threshold = (now - INST_EXPIRY_THRESHOLD) as i64;
            if let Err(e) = tx.execute(
                "DELETE FROM online_insts WHERE last_seen < ?1;",
                [expiry_threshold],
            ) {
                eprintln!("[log_register_node_inst] 清理过期节点失败: {}", e);
            } else {
                self.last_cleanup_time.store(now, Ordering::Relaxed);
            }
        }

        let services_json =
            serde_json::to_string(&service_list).unwrap_or_else(|_| "[]".to_string());

        let _ = tx.execute(
            "INSERT INTO online_insts (inst_id, registered_at, last_seen, capacity, load, services)
             VALUES (?1, ?2, ?2, ?3, ?4, ?5)
             ON CONFLICT(inst_id)
             DO UPDATE SET
                 last_seen = excluded.last_seen,
                 capacity = excluded.capacity,
                 load = excluded.load,
                 services = excluded.services;",
            params![
                inst_id,
                now_i64,
                capacity as i64,
                load as i64,
                services_json
            ],
        );

        if let Err(e) = tx.commit() {
            eprintln!("[log_register_node_inst] 事务提交失败: {}", e);
        }
    }

    /// 心跳更新节点状态
    pub fn log_access(&self, inst_id: &str, load: u64, services: &str) -> bool {
        let service_list: Vec<String> = services.split('|').map(|s| s.to_string()).collect();
        let now = current_timestamp();
        let now_i64 = now as i64;
        let cutoff = (now - self.time_period) as i64;
        let services_json =
            serde_json::to_string(&service_list).unwrap_or_else(|_| "[]".to_string());

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[log_access_node_inst] 获取写连接失败");
                return false;
            }
        };

        let changes = match conn.execute(
            "UPDATE online_insts 
             SET last_seen = ?1, load = ?2, services = ?3 
             WHERE inst_id = ?4 AND last_seen >= ?5;",
            params![now_i64, load as i64, services_json, inst_id, cutoff],
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[log_access_node_inst] 数据库更新失败: {}", e);
                return false;
            }
        };

        changes > 0
    }

    /// 获取活跃节点数量
    pub fn get_number(&self) -> usize {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_node_inst_number] 获取读连接失败");
                return 0;
            }
        };

        match conn.query_row(
            "SELECT COUNT(*) FROM online_insts WHERE last_seen >= ?1;",
            [cutoff],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(count) => count as usize,
            Err(e) => {
                eprintln!("查询活跃节点数失败: {}", e);
                0
            }
        }
    }

    /// 获取活跃节点列表（最多 n 个）
    pub fn get_list(&self, n: usize) -> String {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;
        let limit = (n as i64).min(10000);

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_node_inst_list] 获取读连接失败");
                return "".to_string();
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT inst_id FROM online_insts
             WHERE last_seen >= ?1
             ORDER BY registered_at
             LIMIT ?2;",
        ) {
            Ok(s) => s,
            Err(_) => return "".to_string(),
        };

        let iter = match stmt.query_map([cutoff, limit], |row| row.get::<_, String>(0)) {
            Ok(iter) => iter,
            Err(_) => return "".to_string(),
        };

        let mut ids = Vec::new();
        for id in iter.flatten().take(n) {
            ids.push(id);
        }
        ids.join("|")
    }

    /// 判断节点是否在线
    pub fn is_online(&self, inst_id: &str) -> bool {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[is_node_inst_online] 获取读连接失败");
                return false;
            }
        };

        match conn.query_row(
            "SELECT 1 FROM online_insts WHERE inst_id = ?1 AND last_seen >= ?2;",
            params![inst_id, cutoff],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(_) => true,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(e) => {
                eprintln!("检查节点在线状态失败: {}", e);
                false
            }
        }
    }

    /// 获取节点详细信息
    pub fn get_details(&self, inst_id: &str) -> Option<(u64, u64, Vec<String>)> {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => return None,
        };

        match conn.query_row(
            "SELECT last_seen, load, services FROM online_insts 
             WHERE inst_id = ?1 AND last_seen >= ?2;",
            params![inst_id, cutoff],
            |row| {
                let last_seen: i64 = row.get(0)?;
                let load: i64 = row.get(1)?;
                let services_json: String = row.get(2)?;
                let services: Vec<String> =
                    serde_json::from_str(&services_json).unwrap_or_default();
                Ok((last_seen as u64, load as u64, services))
            },
        ) {
            Ok(result) => Some(result),
            Err(_) => None,
        }
    }

    /// 根据服务名，返回当前在线且支持该服务的最空闲实例ID（空闲能力 = capacity - load 最大）
    /// 如果没有匹配实例，返回 None
    pub fn assign_best_inst_by_service(&self, service: &str) -> Option<String> {
        let now = current_timestamp();
        let cutoff = (now - self.time_period) as i64;

        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_most_idle_instance_by_service] 获取读连接失败");
                return None;
            }
        };

        // 构建查询：筛选在线、支持指定服务、计算空闲能力
        let sql = "
            SELECT inst_id, capacity, load
            FROM online_insts, json_each(services) AS j
            WHERE last_seen >= ?1
                AND j.value = ?
            ORDER BY (capacity - load) DESC
            LIMIT 1;
        ";

        match conn.query_row(sql, params![cutoff, service], |row| {
            let inst_id: String = row.get(0)?;
            Ok(inst_id)
        }) {
            Ok(inst_id) => Some(inst_id),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => {
                eprintln!("[get_most_idle_instance_by_service] 查询失败: {}", e);
                None
            }
        }
    }
}


#[derive(Debug, Clone)]
pub struct OnlineMessages {
    conn: Arc<Mutex<Connection>>,
    time_period: u64,
    last_cleanup_time: Arc<AtomicU64>,
}

impl OnlineMessages {
    pub fn new(conn: Arc<Mutex<Connection>>, time_period: u64) -> Self {
        let last_cleanup_time = Arc::new(AtomicU64::new(0));
        Self {
            conn,
            time_period,
            last_cleanup_time,
        }
    }

    /// ✅ 推送一条消息（幂等）
    pub fn push_message(&self, user_id: String, message: String) {
        let now = current_timestamp_millis(); // ✅ 改为毫秒
        let now_i64 = now as i64;

        let mut conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[push_message] 获取写连接失败");
                return;
            }
        };

        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[push_message] 事务开启失败: {}", e);
                return;
            }
        };

        // 智能清理：仅在需要时执行
        let last_cleanup = self.last_cleanup_time.load(Ordering::Relaxed);
        let should_cleanup = now > last_cleanup + self.time_period; // 检查是否清理过期消息

        if should_cleanup {
            let expiry_threshold = (now - MESSAGE_EXPIRY_THRESHOLD * 1000) as i64; // 转换为毫秒
            if let Err(e) = tx.execute(
                "DELETE FROM online_messages WHERE timestamp < ?1;",
                [expiry_threshold],
            ) {
                eprintln!("[push_message] 清理过期消息失败: {}", e);
            } else {
                self.last_cleanup_time.store(now, Ordering::Relaxed);
            }
        }

        // 插入或忽略（主键冲突时跳过）
        let _ = tx.execute(
            "INSERT INTO online_messages (user_id, timestamp, message)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id, timestamp) DO NOTHING;",
            params![user_id, now_i64, message],
        );

        if let Err(e) = tx.commit() {
            eprintln!("[push_message] 事务提交失败: {}", e);
        }
    }

    /// ✅ 批量推送消息（格式："(ts,msg)|(ts,msg)|..."）
    pub fn push_messages(&self, user_id: String, messages_str: String) -> usize {
        let now = current_timestamp_millis();
        let now_i64 = now as i64;

        let mut conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[push_messages] 获取写连接失败");
                return 0;
            }
        };

        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[push_messages] 事务开启失败: {}", e);
                return 0;
            }
        };

        // 智能清理
        let last_cleanup = self.last_cleanup_time.load(Ordering::Relaxed);
        let should_cleanup = now > last_cleanup + self.time_period; // 检查是否清理过期消息
        if should_cleanup {
            let expiry_threshold = (now - MESSAGE_EXPIRY_THRESHOLD * 1000) as i64;
            if let Err(e) = tx.execute(
                "DELETE FROM online_messages WHERE timestamp < ?1;",
                [expiry_threshold],
            ) {
                eprintln!("[push_messages] 清理过期消息失败: {}", e);
            } else {
                self.last_cleanup_time.store(now, Ordering::Relaxed);
            }
        }

        let parsed = Self::parse_message_entries(&messages_str);
        if parsed.is_empty() {
            let _ = tx.commit();
            return 0;
        }

        const BATCH_SIZE: usize = MAX_VARIABLE_NUMBER / 3; // 每行3个参数
        let mut inserted_count = 0;

        for chunk in parsed.chunks(BATCH_SIZE) {
            let placeholders: Vec<String> = (0..chunk.len()).map(|_| "(?, ?, ?)".to_string()).collect();
            let placeholders_str = placeholders.join(",");

            let sql = format!(
                "INSERT INTO online_messages (user_id, timestamp, message)
                 VALUES {}
                 ON CONFLICT(user_id, timestamp) DO NOTHING;",
                placeholders_str
            );

            let mut ts_values: Vec<i64> = Vec::with_capacity(chunk.len());
            for (ts, _msg) in chunk {
                ts_values.push(*ts as i64);
            }
            let user_id_ref: &dyn ToSql = &user_id;
            let mut params: Vec<&dyn ToSql> = Vec::with_capacity(chunk.len() * 3);
            for (i, (_ts, msg)) in chunk.iter().enumerate() {
                params.push(user_id_ref);
                params.push(&ts_values[i]);
                params.push(msg);
            }

            match tx.execute(&sql, params.as_slice()) {
                Ok(c) => inserted_count += c,
                Err(e) => eprintln!("[push_messages] 批量插入失败: {}", e),
            }
        }

        if let Err(e) = tx.commit() {
            eprintln!("[push_messages] 事务提交失败: {}", e);
        }

        inserted_count
    }

    /// ✅ 获取指定时间戳之后的消息（按时间升序）
    pub fn get_messages(&self, user_id: &str, since_timestamp: u64) -> String {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_messages] 获取读连接失败");
                return String::new();
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT timestamp, message FROM online_messages
             WHERE user_id = ?1 AND timestamp >= ?2
             ORDER BY timestamp ASC;",
        ) {
            Ok(s) => s,
            Err(_) => return String::new(),
        };

        let iter = match stmt.query_map(params![user_id, since_timestamp], |row| {
            let ts: i64 = row.get(0)?;
            let msg: String = row.get(1)?;
            Ok(format!("({},{}),", ts, msg)) // 注意：最后会去掉逗号
        }) {
            Ok(iter) => iter,
            Err(_) => return String::new(),
        };

        let mut parts: Vec<String> = iter
            .filter_map(|r| r.ok())
            .collect();

        // 去掉最后一个逗号，拼接成标准格式
        if parts.is_empty() {
            return String::new();
        }
        parts.pop(); // 移除最后一个多余的逗号
        parts.join("|")
    }

    /// ✅ 获取指定时间戳之后的消息数量
    pub fn get_msg_number_from(&self, user_id: &str, since_timestamp: u64) -> usize {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_msg_number_from] 获取读连接失败");
                return 0;
            }
        };

        match conn.query_row(
            "SELECT COUNT(*) FROM online_messages
             WHERE user_id = ?1 AND timestamp >= ?2;",
            params![user_id, since_timestamp],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(count) => count as usize,
            Err(e) => {
                eprintln!("查询消息数量失败: {}", e);
                0
            }
        }
    }

    /// ✅ 获取总消息数
    pub fn get_msg_number(&self, user_id: &str) -> usize {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_msg_number] 获取读连接失败");
                return 0;
            }
        };

        match conn.query_row(
            "SELECT COUNT(*) FROM online_messages WHERE user_id = ?1;",
            [user_id],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(count) => count as usize,
            Err(e) => {
                eprintln!("查询总消息数失败: {}", e);
                0
            }
        }
    }

    /// ✅ 获取最新消息的时间戳
    pub fn get_last_timestamp(&self, user_id: &str) -> Option<u64> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_last_timestamp] 获取读连接失败");
                return None;
            }
        };

        match conn.query_row(
            "SELECT MAX(timestamp) FROM online_messages WHERE user_id = ?1;",
            [user_id],
            |row| row.get::<_, Option<i64>>(0),
        ) {
            Ok(Some(ts)) => Some(ts as u64),
            Ok(None) => None,
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => {
                eprintln!("获取最新时间戳失败: {}", e);
                None
            }
        }
    }

    /// ✅ 获取最旧消息的时间戳
    pub fn get_oldest_timestamp(&self, user_id: &str) -> Option<u64> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_oldest_timestamp] 获取读连接失败");
                return None;
            }
        };

        match conn.query_row(
            "SELECT MIN(timestamp) FROM online_messages WHERE user_id = ?1;",
            [user_id],
            |row| row.get::<_, Option<i64>>(0),
        ) {
            Ok(Some(ts)) => Some(ts as u64),
            Ok(None) => None,
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => {
                eprintln!("获取最旧时间戳失败: {}", e);
                None
            }
        }
    }

    /// ✅ 获取所有时间戳（升序）
    pub fn get_timestamps(&self, user_id: &str) -> Vec<u64> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_timestamps] 获取读连接失败");
                return vec![];
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT timestamp FROM online_messages
             WHERE user_id = ?1
             ORDER BY timestamp ASC;",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let iter = match stmt.query_map([user_id], |row| row.get::<_, i64>(0)) {
            Ok(iter) => iter,
            Err(_) => return vec![],
        };

        iter.filter_map(|r| r.ok()).map(|ts| ts as u64).collect()
    }

    /// ✅ 获取单条消息内容
    pub fn get_message(&self, user_id: &str, timestamp: u64) -> Option<String> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[get_message] 获取读连接失败");
                return None;
            }
        };

        match conn.query_row(
            "SELECT message FROM online_messages
             WHERE user_id = ?1 AND timestamp = ?2;",
            params![user_id, timestamp],
            |row| row.get::<_, Option<String>>(0),
        ) {
            Ok(Some(msg)) => Some(msg),
            Ok(None) => None,
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => {
                eprintln!("获取单条消息失败: {}", e);
                None
            }
        }
    }

    /// ✅ 删除指定时间戳之前的所有消息（含该时间戳）
    pub fn remove_old_messages(&self, user_id: String, until_timestamp: u64) {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                eprintln!("[remove_old_messages] 获取写连接失败");
                return;
            }
        };

        let _ = conn.execute(
            "DELETE FROM online_messages WHERE user_id = ?1 AND timestamp <= ?2;",
            params![user_id, until_timestamp as i64],
        );
    }

    /// ✅ 解析输入字符串 "(ts,msg)|(ts,msg)" → [(ts, msg)]
    fn parse_message_entries(input: &str) -> Vec<(u64, String)> {
        input.split('|')
            .filter_map(|part| {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    return None;
                }

                let (ts, msg) = trimmed
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|s| s.split_once(','))?;

                let ts = ts.trim().parse().ok()?;
                let msg = msg.trim().to_string();

                Some((ts, msg))
            })
            .collect()
    }
}