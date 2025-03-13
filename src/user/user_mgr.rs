use std::collections::{VecDeque, HashSet, BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use sled::Tree;
use tracing::debug;



#[derive(Debug, Clone, Default)]
struct CacheState {
    user_set: HashSet<String>,
    last_update: u64,
}

#[derive(Debug, Clone, Default)]
struct DomainState {
    nodes_num: usize,
    users_num: usize,
    nodes_top_list: Vec<String>,
}


#[derive(Debug, Clone)]
pub struct OnlineUsers {
    // 不可变配置参数
    time_period: u64,
    cache_update_interval: u64,

    // 域变量
    domain: Arc<std::sync::RwLock<DomainState>>,

    // 多线程状态变量
    registered_users: Arc<std::sync::RwLock<HashSet<String>>>,
    user_queue: Arc<std::sync::Mutex<VecDeque<(String, u64)>>>,
    cache: Arc<std::sync::RwLock<CacheState>>,
}

impl OnlineUsers {
    pub fn new(time_period: u64, cache_update_interval: u64) -> Self {
        Self {
            time_period,
            cache_update_interval,
            domain: std::sync::RwLock::new(DomainState::default()).into(),
            registered_users: std::sync::RwLock::new(HashSet::new()).into(),
            user_queue: std::sync::Mutex::new(VecDeque::new()).into(),
            cache: std::sync::RwLock::new(CacheState::default()).into(),
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

    pub fn log_access(&self, user_id: String) -> bool{
        {
            let registered = self.registered_users.read().unwrap();
            if !registered.contains(&user_id) {
                return false;
            }
        }

        let now = Self::current_timestamp();
        {
            let mut queue = self.user_queue.lock().unwrap();
            queue.push_back((user_id, now));
        }
        true
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
        let domain = self.domain.read().unwrap();
        (domain.nodes_num, domain.users_num)
    }

    pub fn get_nodes_top_list(&self) -> String  {
        let domain = self.domain.read().unwrap();
        domain.nodes_top_list.join("|")
    }

    pub fn set_nodes_users(&mut self, nodes: usize, users: usize, top_list: String) {
        let mut domain = self.domain.write().unwrap();
        domain.nodes_num = nodes;
        domain.users_num = users;
        if !top_list.is_empty() {
            domain.nodes_top_list = top_list.split('|').map(|id| id.trim().to_string()).collect();
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
pub struct AsyncOnlineUsers {
    // 不可变配置参数
    time_period: u64,
    cache_update_interval: u64,

    // 域变量（使用tokio异步锁）
    domain: Arc<tokio::sync::RwLock<DomainState>>,

    // 状态变量（使用tokio异步锁）
    registered_users: Arc<tokio::sync::RwLock<HashSet<String>>>,
    user_queue: Arc<tokio::sync::Mutex<VecDeque<(String, u64)>>>,
    cache: Arc<tokio::sync::RwLock<CacheState>>,
}



impl AsyncOnlineUsers {
    pub fn new(time_period: u64, cache_update_interval: u64) -> Self {
        Self {
            time_period,
            cache_update_interval,
            domain: Arc::new(tokio::sync::RwLock::new(DomainState::default())),
            registered_users: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
            user_queue: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            cache: Arc::new(tokio::sync::RwLock::new(CacheState::default())),
        }
    }

    /// 异步注册新用户
    pub async fn log_register(&self, user_id: String) {
        {
            let mut registered = self.registered_users.write().await;
            registered.insert(user_id.clone());
        }
        let now = Self::current_timestamp();
        {
            let mut queue = self.user_queue.lock().await;
            queue.push_back((user_id, now));
        }
    }

    /// 异步访问日志
    pub async fn log_access(&self, user_id: String) -> bool {
        {
            let registered = self.registered_users.read().await;
            if !registered.contains(&user_id) {
                return false;
            }
        }

        let now = Self::current_timestamp();
        {
            let mut queue = self.user_queue.lock().await;
            queue.push_back((user_id, now));
        }
        true
    }

    /// 异步获取在线用户数
    pub async fn get_number(&self) -> usize {
        let now = Self::current_timestamp();

        // 第一层缓存检查
        {
            let cache = self.cache.read().await;
            if now - cache.last_update < self.cache_update_interval {
                return cache.user_set.len();
            }
        }

        // 获取写锁更新缓存
        let mut cache = self.cache.write().await;

        // 第二层缓存检查
        if now - cache.last_update < self.cache_update_interval {
            return cache.user_set.len();
        }

        // 清理过期数据
        let mut queue = self.user_queue.lock().await;
        Self::cleanup_old_users(&mut queue, self.time_period, now);

        // 重建缓存
        let mut user_set = HashSet::with_capacity(queue.len());
        for (user_id, _) in queue.iter() {
            user_set.insert(user_id.clone());
        }

        // 更新缓存
        *cache = CacheState {
            user_set,
            last_update: now,
        };

        cache.user_set.len()
    }
    
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
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
}



#[derive(Debug, Clone)]
pub(crate) struct MessageQueue {
    data: Arc<std::sync::RwLock<HashMap<String, BTreeMap<u64, String>>>>,
    global_vars: Arc<std::sync::Mutex<Tree>>,
}

impl MessageQueue {
    pub fn new(global_vars: Arc<std::sync::Mutex<Tree>>) -> Self {
        Self {
            data: Arc::new(std::sync::RwLock::new(HashMap::new())),
            global_vars: global_vars.clone(),
        }
    }

    // 加载特定用户的数据
    fn load_user_data(&self, user_id: &str) {
        {
            let lock = self.data.read().unwrap();
            if lock.contains_key(user_id) {
                return;
            }
        }

        // 内存中没有时从存储加载
        let key = format!("msg_list_{}", user_id);
        if let Ok(Some(data_str)) = self.global_vars.lock().unwrap().get(&key) {
            if let Ok(data_str) = String::from_utf8(data_str.to_vec()) {
                let mut lock = self.data.write().unwrap();
                // 双重检查避免重复插入
                if !lock.contains_key(user_id) {
                    lock.insert(user_id.to_string(), self.parse_storage_str(&data_str));
                }
            }
        }
    }

    // 保存特定用户数据到存储
    fn save_user_data(&self, user_id: &str) {
        let key = format!("msg_list_{}", user_id);
        let data_str = {
            let lock = self.data.read().unwrap();
            if let Some(user_data) = lock.get(user_id) {
                self.generate_storage_str(user_data)
            } else {
                String::new()
            }
        };

        self.global_vars
            .lock()
            .unwrap()
            .insert(key, data_str.as_bytes())
            .expect("Failed to save to storage");
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

    // 生成存储字符串
    fn generate_storage_str(&self, data: &BTreeMap<u64, String>) -> String {
        data.iter()
            .map(|(ts, msg)| format!("({},{})", ts, msg))
            .collect::<Vec<_>>()
            .join("|")
    }

    pub fn push_message(&self, user_id: &str, msg: String) {
        let timestamp = Self::current_timestamp();
        {
            let mut lock = self.data.write().unwrap();
            let user_data = lock.entry(user_id.to_string()).or_default();
            user_data.insert(timestamp, msg);
        }
        self.save_user_data(user_id);
    }

    pub fn push_messages(&self, user_id: &str, messages: String) -> usize {
        let parsed = Self::parse_message_entries(&messages);
        if parsed.is_empty() {
            return 0;
        }

        let mut lock = self.data.write().unwrap();
        let user_data = lock.entry(user_id.to_string()).or_default();
        let mut count = 0;

        for (ts, msg) in parsed {
            if user_data.insert(ts, msg).is_none() {
                count += 1;
            }
        }

        self.save_user_data(user_id);
        count
    }

    pub fn remove_old_messages(&self, user_id: &str, timestamp: u64) {
        {
            let mut lock = self.data.write().unwrap();
            if let Some(user_data) = lock.get_mut(user_id) {
                let old_keys: Vec<u64> = user_data.range(..timestamp).map(|(&k, _)| k).collect();
                for key in old_keys {
                    user_data.remove(&key);
                }
            }
        }
        self.save_user_data(user_id);
    }

    pub fn get_messages(&self, user_id: &str, timestamp: u64) -> String {
        self.load_user_data(user_id); // 确保加载最新数据
        let lock = self.data.read().unwrap();
        lock.get(user_id)
            .map(|user_data| 
                user_data.range(timestamp..)
                    .map(|(ts, msg)| format!("({},{})", ts, msg))
                    .collect::<Vec<_>>()
                    .join("|")
            )
            .unwrap_or_default()
    }

    /// 获取最新消息的时间戳（返回Option确保空队列安全）
    pub fn get_last_timestamp(&self, user_id: &str) -> Option<u64> {
        self.load_user_data(user_id);
        let lock = self.data.read().unwrap();
        lock.get(user_id)
            .and_then(|user_data| user_data.last_key_value().map(|(k, _)| *k))
    }

    /// 获取最旧消息的时间戳（返回Option确保空队列安全）
    pub fn get_oldest_timestamp(&self,  user_id: &str) -> Option<u64> {
        self.load_user_data(user_id);
        let lock = self.data.read().unwrap();
        lock.get(user_id)
            .and_then(|user_data| user_data.first_key_value().map(|(k, _)| *k))
    }

    /// 获取所有时间戳的有序列表（升序排列）
    pub fn get_timestamps(&self, user_id: &str) -> Vec<u64> {
        self.load_user_data(user_id);
        let lock = self.data.read().unwrap();
        lock.get(user_id)
            .map(|user_data| user_data.keys().cloned().collect::<Vec<u64>>())
            .unwrap_or_default()
    }

    pub fn get_msg_number(&self, user_id: &str) -> usize {
        self.load_user_data(user_id);
        let lock = self.data.read().unwrap();
        lock.get(user_id)
            .map(|user_data| user_data.len())
           .unwrap_or_default()
    }

    pub fn get_msg_number_from(&self, user_id: &str, timestamp: u64) -> usize {
        self.load_user_data(user_id);
        let lock = self.data.read().unwrap();
        lock.get(user_id)
            .map(|user_data| user_data.range(timestamp..).count()) // 使用range过滤时间戳
            .unwrap_or_default()
    }

    /// 获取指定时间戳的消息内容（返回Option明确存在性）
    pub fn get_message(&self, user_id: &str, timestamp: u64) -> Option<String> {
        self.load_user_data(user_id);
        let lock = self.data.read().unwrap();
        lock.get(user_id)
            .and_then(|user_data| user_data.get(&timestamp).cloned())
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64
    }
}

