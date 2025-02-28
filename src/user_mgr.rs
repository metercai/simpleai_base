use std::collections::{VecDeque, HashSet, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Mutex, RwLock};
use std::sync::Arc;
use sled::Tree;
use tracing::debug;


#[derive(Debug, Clone)]
pub struct OnlineUsers {
    // 不可变配置参数
    time_period: u64,
    cache_update_interval: u64,

    // 域变量
    nodes_num: usize,
    users_num: usize,
    nodes_top_list: Vec<String>,

    // 多线程状态变量
    registered_users: Arc<RwLock<HashSet<String>>>,
    user_queue: Arc<Mutex<VecDeque<(String, u64)>>>,
    cache: Arc<RwLock<CacheState>>,
}

#[derive(Debug, Clone, Default)]
struct CacheState {
    user_set: HashSet<String>,
    last_update: u64,
}

impl OnlineUsers {
    pub fn new(time_period: u64, cache_update_interval: u64) -> Self {
        Self {
            time_period,
            cache_update_interval,
            nodes_num: 0,
            users_num: 0,
            nodes_top_list: vec![],
            registered_users: RwLock::new(HashSet::new()).into(),
            user_queue: Mutex::new(VecDeque::new()).into(),
            cache: RwLock::new(CacheState::default()).into(),
        }
    }

    /// 注册新用户（幂等操作）
    pub fn log_register(&self, user_id: String) {
        {
            let mut registered = self.registered_users.write().unwrap();
            registered.insert(user_id.clone());
        }
        let now = Self::current_timestamp();
        {
            let mut queue = self.user_queue.lock().unwrap();
            queue.push_back((user_id, now));
        }
    }

    pub fn log_access(&self, user_id: String) {
        {
            let registered = self.registered_users.read().unwrap();
            if !registered.contains(&user_id) {
                return;
            }
        }

        let now = Self::current_timestamp();
        {
            let mut queue = self.user_queue.lock().unwrap();
            queue.push_back((user_id, now));
        }
    }

    pub fn log_access_batch(&self, batch_ids: String) {
        let now = Self::current_timestamp();
        if !batch_ids.is_empty() {
            let mut queue = self.user_queue.lock().unwrap();
            batch_ids
                .split('|') // 按 '|' 分隔字符串
                .map(|id| id.trim()) // 去除空白字符
                .for_each(|id| {
                    queue.push_back((id.to_string(), now));
                });
        }
    }

    pub fn get_number(&self) -> usize {
        let now = Self::current_timestamp();

        // 第一层缓存检查（无锁）
        {
            let cache = self.cache.read().unwrap();
            if now - cache.last_update < self.cache_update_interval {
                return cache.user_set.len();
            }
        }

        // 获取写锁更新缓存
        let mut cache = self.cache.write().unwrap();

        // 第二层缓存检查（避免重复更新）
        if now - cache.last_update < self.cache_update_interval {
            return cache.user_set.len();
        }

        // 获取队列锁并清理过期数据
        let mut queue = self.user_queue.lock().unwrap();
        Self::cleanup_old_users(&mut queue, self.time_period, now);

        // 重建缓存
        let mut user_set = HashSet::with_capacity(queue.len());
        for (user_id, _) in queue.iter() {
            user_set.insert(user_id.clone());
        }

        // 更新缓存状态
        *cache = CacheState {
            user_set,
            last_update: now,
        };

        cache.user_set.len()
    }

    pub fn get_list(&self, n: usize) -> String {
        self.get_number();
        let cache = self.cache.read().unwrap();
        let actual_count = if n == 0 || n > cache.user_set.len() {
            cache.user_set.len()
        } else {
            n
        };
        cache.user_set
            .iter()
            .take(actual_count)
            .cloned()
            .collect::<Vec<_>>()
            .join("|")
    }

    pub fn is_online(&self, user_id: &str) -> bool {
        self.get_number();
        let cache = self.cache.read().unwrap();
        cache.user_set.iter().any(|id| id == user_id)
    }

    pub fn get_full_list(&self) -> String {
        self.get_number();
        let cache = self.cache.read().unwrap();
        cache.user_set.iter().cloned().collect::<Vec<_>>().join("|")
    }

    pub fn get_nodes_users(&self) -> (usize, usize)  {
        (self.nodes_num, self.users_num)
    }

    pub fn get_nodes_top_list(&self) -> String  {
        self.nodes_top_list.join("|")
    }

    pub fn set_nodes_users(&mut self, nodes: usize, users: usize, top_list: String) {
        self.nodes_num = nodes;
        self.users_num = users;
        if !top_list.is_empty() {
            self.nodes_top_list = top_list.split('|').map(|id| id.trim().to_string()).collect();
        }
    }

    fn cleanup_old_users(
        queue: &mut VecDeque<(String, u64)>,
        time_period: u64,
        current_time: u64
    ) {
        while let Some(&(_, ts)) = queue.front() {
            if ts + time_period < current_time {
                queue.pop_front();
            } else {
                break;
            }
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }
}




#[derive(Debug, Clone)]
pub(crate) struct MessageQueue {
    data: Arc<RwLock<BTreeMap<u64, String>>>, // 修改为直接存储String
    global_vars: Arc<Mutex<Tree>>,
}

impl MessageQueue {
    pub fn new(global_vars: Arc<Mutex<Tree>>) -> Self {
        let instance = Self {
            data: Arc::new(RwLock::new(BTreeMap::new())),
            global_vars: global_vars.clone(),
        };

        // 从存储初始化
        if let Ok(Some(data_str)) = global_vars.lock().unwrap().get("msg_list") {
            if let Ok(data_str) = String::from_utf8(data_str.to_vec()) {
                let mut lock = instance.data.write().unwrap();
                *lock = instance.parse_storage_str(&data_str);
            }
        }
        instance
    }

    fn parse_message_entries(input: &str) -> Vec<(u64, String)> {
        input.split('|')
            .filter_map(|part| {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    return None;
                }

                // 解析形如 (timestamp,message) 的格式
                let (ts, msg) = trimmed
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|s| s.split_once(','))?;

                // 转换时间戳并处理空格
                let ts = ts.trim().parse().ok()?;
                let msg = msg.trim().to_string();

                Some((ts, msg))
            })
            .collect()
    }


    fn parse_storage_str(&self, data_str: &str) -> BTreeMap<u64, String> {
        Self::parse_message_entries(data_str)
            .into_iter()
            .collect()
    }

    // 持久化存储方法
    fn save_to_storage(&self) {
        let data_str = {
            let lock = self.data.read().unwrap();
            self.generate_storage_str(&lock)
        };

        self.global_vars
            .lock()
            .unwrap()
            .insert("msg_list", data_str.as_bytes())
            .expect("Failed to save to storage");
    }

    // 生成存储字符串
    fn generate_storage_str(&self, data: &BTreeMap<u64, String>) -> String {
        data.iter()
            .map(|(ts, msg)| format!("({},{})", ts, msg))
            .collect::<Vec<_>>()
            .join("|")
    }

    pub fn push_message(&self, msg: String) {
        let timestamp = Self::current_timestamp();
        {
            let mut lock = self.data.write().unwrap();
            lock.insert(timestamp, msg); // 直接插入/覆盖
        }
        self.save_to_storage();
    }

    pub fn push_messages(&self, messages: String) -> usize {
        let parsed = Self::parse_message_entries(&messages);
        if parsed.is_empty() {
            return 0;
        }

        let mut lock = self.data.write().unwrap();
        let mut count = 0;

        // 批量插入并计数
        for (ts, msg) in parsed {
            if lock.insert(ts, msg).is_none() {
                count += 1;
            }
        }

        self.save_to_storage();
        count
    }

    pub fn remove_old_messages(&self, timestamp: u64) {
        {
            let mut lock = self.data.write().unwrap();
            let old_keys: Vec<u64> = lock.range(..timestamp).map(|(&k, _)| k).collect();
            for key in old_keys {
                lock.remove(&key);
            }
        }
        self.save_to_storage();
    }

    pub fn get_messages(&self, timestamp: u64) -> String {
        let lock = self.data.read().unwrap();
        lock.range(timestamp..)
            .map(|(ts, msg)| format!("({},{})", ts, msg))
            .collect::<Vec<_>>()
            .join("|")
    }

    /// 获取最新消息的时间戳（返回Option确保空队列安全）
    pub fn get_last_timestamp(&self) -> Option<u64> {
        let lock = self.data.read().unwrap();
        lock.last_key_value().map(|(k, _)| *k)
    }

    /// 获取最旧消息的时间戳（返回Option确保空队列安全）
    pub fn get_oldest_timestamp(&self) -> Option<u64> {
        let lock = self.data.read().unwrap();
        lock.first_key_value().map(|(k, _)| *k)
    }

    /// 获取所有时间戳的有序列表（升序排列）
    pub fn get_timestamps(&self) -> Vec<u64> {
        let lock = self.data.read().unwrap();
        lock.keys().cloned().collect()
    }

    /// 获取指定时间戳的消息内容（返回Option明确存在性）
    pub fn get_message(&self, timestamp: u64) -> Option<String> {
        let lock = self.data.read().unwrap();
        lock.get(&timestamp).cloned()
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64
    }
}

