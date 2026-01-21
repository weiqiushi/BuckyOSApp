use if_addrs::get_if_addrs;

#[tauri::command]
pub fn local_ipv4_list() -> Result<Vec<String>, String> {
    let interfaces = get_if_addrs().map_err(|e| e.to_string())?;
    let mut ips: Vec<String> = interfaces
        .into_iter()
        .filter_map(|iface| match iface.ip() {
            std::net::IpAddr::V4(addr) if !addr.is_loopback() => Some(addr.to_string()),
            _ => None,
        })
        .collect();
    ips.sort();
    ips.dedup();
    Ok(ips)
}
