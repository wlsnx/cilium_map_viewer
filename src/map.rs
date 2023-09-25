use anyhow::{Context, Result};
use libbpf_rs::MapFlags;
use libbpf_rs::{query::MapInfo, Map, MapHandle};
use libbpf_sys;
use plain::Plain;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::ptr;
use tuitable::TuiTable;

pub fn dump<K, V>(map: &MapHandle, percpu: bool) -> Result<(Vec<Vec<String>>, Vec<&'static str>)>
where
    K: TuiTable + Default + Plain,
    V: TuiTable + Default + Plain,
{
    let mut header = vec![];
    if percpu {
        header.push("cpu");
    }
    header.extend(K::header());
    header.push("│");
    header.extend(V::header());
    let mut rows = vec![];
    for mut key in map.keys().take(100) {
        let mut k = K::default();
        key.extend(vec![0; size_of::<K>().saturating_sub(key.len())]);
        k.copy_from_bytes(&key).unwrap();
        let mut values = if percpu {
            map.lookup_percpu(&key, MapFlags::empty())?.unwrap()
        } else {
            vec![map
                .lookup(&key[..map.key_size() as usize], MapFlags::empty())?
                .unwrap()]
        };
        for (cpu, value) in values.iter_mut().enumerate() {
            let mut row = vec![];
            if percpu {
                row.push(cpu.to_string());
            }
            row.extend(k.row());
            row.push("│".to_string());
            value.extend(vec![0; size_of::<V>().saturating_sub(value.len())]);
            let mut v = V::default();
            v.copy_from_bytes(&value).unwrap();
            row.extend(v.row());
            rows.push(row);
        }
    }
    Ok((rows, header))
}
