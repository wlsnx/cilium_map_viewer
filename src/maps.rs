use anyhow::{Context, Result};
use libbpf_rs::MapFlags;
use libbpf_rs::{query::MapInfo, Map, MapHandle};
use libbpf_sys;
use plain::Plain;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::ptr;
use tuitable::TuiTable;

pub fn dump<K, V>(id: u32) -> Result<(Vec<Vec<String>>, Vec<&'static str>, String)>
where
    K: TuiTable + Default + Plain,
    V: TuiTable + Default + Plain,
{
    let mut header = K::header();
    header.extend(V::header());
    let map = MapHandle::from_map_id(id).context("a")?;
    let mut rows = vec![];
    for mut key in MapKeyIter::new(&map, map.key_size()) {
        key.extend(vec![0; size_of::<K>().saturating_sub(key.len())]);
        let mut k = K::default();
        k.copy_from_bytes(&key).unwrap();
        let mut value = map
            .lookup(&key[..map.key_size() as usize], MapFlags::empty())
            .context("b")?
            .unwrap();
        value.extend(vec![0; size_of::<V>().saturating_sub(value.len())]);
        let mut v = V::default();
        v.copy_from_bytes(&value).unwrap();
        let mut row = k.row();
        row.extend(v.row());
        rows.push(row);
    }
    Ok((rows, header, map.name().to_string()))
}

// 新版 libbpf-rs 把 `Map::from_map_id` 移动到 `MapHandle::from_map_id` 了
// 我们从 map id 只能获取到 `MapHandle` ，没法从 `MapHandle` 获取 `Map`
// `Map` deref 到 `MapHandle`，`MapHandle` 有 `lookup` 方法却没有 `keys` 方法
// 所以只能把 `Map::keys` 复制过来了
#[derive(Debug)]
pub struct MapKeyIter<'a> {
    map: &'a MapHandle,
    prev: Option<Vec<u8>>,
    next: Vec<u8>,
}

impl<'a> MapKeyIter<'a> {
    fn new(map: &'a MapHandle, key_size: u32) -> Self {
        Self {
            map,
            prev: None,
            next: vec![0; key_size as usize],
        }
    }
}

impl Iterator for MapKeyIter<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let prev = self.prev.as_ref().map_or(ptr::null(), |p| p.as_ptr());

        let ret = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                self.map.as_fd().as_raw_fd(),
                prev as _,
                self.next.as_mut_ptr() as _,
            )
        };
        if ret != 0 {
            None
        } else {
            self.prev = Some(self.next.clone());
            Some(self.next.clone())
        }
    }
}
