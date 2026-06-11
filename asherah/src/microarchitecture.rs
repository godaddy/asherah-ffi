use std::fs;
use std::io;
use std::path::Path;

pub const LINUX_CPU_VULNERABILITIES_DIR: &str = "/sys/devices/system/cpu/vulnerabilities";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpuVulnerabilityExposure {
    NotAffected,
    Mitigated,
    Vulnerable,
    Unknown,
}

impl CpuVulnerabilityExposure {
    pub fn requires_operator_attention(&self) -> bool {
        matches!(self, Self::Vulnerable | Self::Unknown)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuVulnerabilityStatus {
    pub name: String,
    pub status: String,
    pub exposure: CpuVulnerabilityExposure,
}

pub fn classify_cpu_vulnerability_status(status: &str) -> CpuVulnerabilityExposure {
    let normalized = status.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return CpuVulnerabilityExposure::Unknown;
    }
    if normalized == "not affected" || normalized.starts_with("not affected\n") {
        return CpuVulnerabilityExposure::NotAffected;
    }
    if normalized.contains("vulnerable") {
        return CpuVulnerabilityExposure::Vulnerable;
    }
    if normalized.starts_with("mitigation:") {
        return CpuVulnerabilityExposure::Mitigated;
    }
    CpuVulnerabilityExposure::Unknown
}

pub fn cpu_vulnerabilities_from_dir(
    dir: impl AsRef<Path>,
) -> io::Result<Vec<CpuVulnerabilityStatus>> {
    let entries = match fs::read_dir(dir.as_ref()) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut statuses = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let status = fs::read_to_string(entry.path())?.trim().to_string();
        statuses.push(CpuVulnerabilityStatus {
            exposure: classify_cpu_vulnerability_status(&status),
            name,
            status,
        });
    }
    statuses.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(statuses)
}

pub fn host_cpu_vulnerabilities() -> io::Result<Vec<CpuVulnerabilityStatus>> {
    cpu_vulnerabilities_from_dir(LINUX_CPU_VULNERABILITIES_DIR)
}

pub fn cpu_vulnerabilities_requiring_attention_from_dir(
    dir: impl AsRef<Path>,
) -> io::Result<Vec<CpuVulnerabilityStatus>> {
    Ok(cpu_vulnerabilities_from_dir(dir)?
        .into_iter()
        .filter(|status| status.exposure.requires_operator_attention())
        .collect())
}

pub fn host_cpu_vulnerabilities_requiring_attention() -> io::Result<Vec<CpuVulnerabilityStatus>> {
    cpu_vulnerabilities_requiring_attention_from_dir(LINUX_CPU_VULNERABILITIES_DIR)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "asherah-cpu-vulnerabilities-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn classifies_kernel_cpu_vulnerability_statuses() {
        assert_eq!(
            classify_cpu_vulnerability_status("Not affected"),
            CpuVulnerabilityExposure::NotAffected
        );
        assert_eq!(
            classify_cpu_vulnerability_status("Mitigation: Enhanced IBRS; IBPB"),
            CpuVulnerabilityExposure::Mitigated
        );
        assert_eq!(
            classify_cpu_vulnerability_status("Vulnerable: Clear CPU buffers attempted"),
            CpuVulnerabilityExposure::Vulnerable
        );
        assert_eq!(
            classify_cpu_vulnerability_status("Mitigation: PTE Inversion; SMT vulnerable"),
            CpuVulnerabilityExposure::Vulnerable
        );
        assert_eq!(
            classify_cpu_vulnerability_status("Unknown: Dependent on hypervisor status"),
            CpuVulnerabilityExposure::Unknown
        );
    }

    #[test]
    fn reads_and_filters_cpu_vulnerabilities_from_sysfs_shape() {
        let dir = temp_dir();
        fs::write(dir.join("meltdown"), "Not affected\n").unwrap();
        fs::write(dir.join("spectre_v2"), "Mitigation: Enhanced IBRS\n").unwrap();
        fs::write(
            dir.join("l1tf"),
            "Mitigation: PTE Inversion; SMT vulnerable\n",
        )
        .unwrap();
        fs::write(dir.join("retbleed"), "Vulnerable\n").unwrap();
        fs::create_dir(dir.join("not-a-file")).unwrap();

        let all = cpu_vulnerabilities_from_dir(&dir).unwrap();
        assert_eq!(
            all.iter()
                .map(|status| status.name.as_str())
                .collect::<Vec<_>>(),
            vec!["l1tf", "meltdown", "retbleed", "spectre_v2"]
        );

        let attention = cpu_vulnerabilities_requiring_attention_from_dir(&dir).unwrap();
        assert_eq!(
            attention
                .iter()
                .map(|status| status.name.as_str())
                .collect::<Vec<_>>(),
            vec!["l1tf", "retbleed"]
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_cpu_vulnerability_directory_is_empty() {
        let dir = temp_dir();
        fs::remove_dir_all(&dir).unwrap();

        let statuses = cpu_vulnerabilities_from_dir(&dir).unwrap();
        assert!(statuses.is_empty());
    }
}
