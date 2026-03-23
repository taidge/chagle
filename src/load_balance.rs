use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A group of services for load balancing
#[derive(Debug)]
pub struct LoadBalanceGroup {
    pub name: String,
    pub group_key: Option<String>,
    members: Vec<String>, // service names
    counter: AtomicUsize,
}

impl LoadBalanceGroup {
    pub fn new(name: String, group_key: Option<String>) -> Self {
        Self {
            name,
            group_key,
            members: Vec::new(),
            counter: AtomicUsize::new(0),
        }
    }

    pub fn add_member(&mut self, service_name: String) {
        if !self.members.contains(&service_name) {
            self.members.push(service_name);
        }
    }

    pub fn remove_member(&mut self, service_name: &str) {
        self.members.retain(|m| m != service_name);
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get the next member using round-robin selection
    pub fn next_member(&self) -> Option<&str> {
        if self.members.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.members.len();
        Some(&self.members[idx])
    }

    /// Get a random member
    pub fn random_member(&self) -> Option<&str> {
        if self.members.is_empty() {
            return None;
        }
        let idx = rand::random::<usize>() % self.members.len();
        Some(&self.members[idx])
    }

    /// Validate that a group key matches
    pub fn validate_key(&self, key: Option<&str>) -> bool {
        match (&self.group_key, key) {
            (None, None) => true,
            (Some(expected), Some(provided)) => expected == provided,
            _ => false,
        }
    }
}

/// Manager for all load balance groups
#[derive(Debug)]
pub struct LoadBalanceManager {
    groups: HashMap<String, LoadBalanceGroup>,
}

impl LoadBalanceManager {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Register a service into a load balance group
    pub fn register(
        &mut self,
        group_name: &str,
        group_key: Option<&str>,
        service_name: &str,
    ) -> Result<(), String> {
        if let Some(group) = self.groups.get_mut(group_name) {
            // Validate key
            if !group.validate_key(group_key) {
                return Err(format!("Group key mismatch for group '{}'", group_name));
            }
            group.add_member(service_name.to_string());
        } else {
            let mut group =
                LoadBalanceGroup::new(group_name.to_string(), group_key.map(|s| s.to_string()));
            group.add_member(service_name.to_string());
            self.groups.insert(group_name.to_string(), group);
        }
        Ok(())
    }

    /// Unregister a service from its group
    pub fn unregister(&mut self, group_name: &str, service_name: &str) {
        if let Some(group) = self.groups.get_mut(group_name) {
            group.remove_member(service_name);
            if group.is_empty() {
                self.groups.remove(group_name);
            }
        }
    }

    /// Get the next service for a group (round-robin)
    pub fn next_service(&self, group_name: &str) -> Option<&str> {
        self.groups.get(group_name)?.next_member()
    }

    /// Get a random service for a group
    pub fn random_service(&self, group_name: &str) -> Option<&str> {
        self.groups.get(group_name)?.random_member()
    }

    pub fn get_group(&self, group_name: &str) -> Option<&LoadBalanceGroup> {
        self.groups.get(group_name)
    }

    pub fn groups(&self) -> &HashMap<String, LoadBalanceGroup> {
        &self.groups
    }
}

impl Default for LoadBalanceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        let mut group = LoadBalanceGroup::new("test".to_string(), None);
        group.add_member("a".to_string());
        group.add_member("b".to_string());
        group.add_member("c".to_string());

        assert_eq!(group.next_member(), Some("a"));
        assert_eq!(group.next_member(), Some("b"));
        assert_eq!(group.next_member(), Some("c"));
        assert_eq!(group.next_member(), Some("a"));
    }

    #[test]
    fn test_group_key_validation() {
        let group = LoadBalanceGroup::new("test".to_string(), Some("secret".to_string()));
        assert!(group.validate_key(Some("secret")));
        assert!(!group.validate_key(Some("wrong")));
        assert!(!group.validate_key(None));
    }

    #[test]
    fn test_manager() {
        let mut mgr = LoadBalanceManager::new();
        mgr.register("web", Some("key1"), "web-1").unwrap();
        mgr.register("web", Some("key1"), "web-2").unwrap();

        // Wrong key should fail
        assert!(mgr.register("web", Some("wrong"), "web-3").is_err());

        assert!(mgr.next_service("web").is_some());

        mgr.unregister("web", "web-1");
        assert_eq!(mgr.get_group("web").unwrap().member_count(), 1);

        mgr.unregister("web", "web-2");
        assert!(mgr.get_group("web").is_none());
    }
}
