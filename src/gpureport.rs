use serde::{Deserialize, Serialize};
use pyo3::prelude::*;

/// Report specifying the capabilities of the GPUs on the system.
///
/// Must be synchronized with the definition on tests/src/report.rs.
#[derive(Deserialize, Serialize)]
pub struct GpuReport {
    pub devices: Vec<AdapterReport>,
}

impl GpuReport {
    pub fn generate() -> Self {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::util::backend_bits_from_env().unwrap_or_default(),
            flags: wgpu::InstanceFlags::debugging().with_env(),
            dx12_shader_compiler: wgpu::util::dx12_shader_compiler_from_env().unwrap_or_default(),
            gles_minor_version: wgpu::util::gles_minor_version_from_env().unwrap_or_default(),
        });
        let adapters = instance.enumerate_adapters(wgpu::Backends::all());

        let mut devices = Vec::with_capacity(adapters.len());
        for adapter in adapters {
            let info = adapter.get_info();
            devices.push(AdapterReport {
                name: info.name,
                vendor: info.vendor,
                device: info.device,
                device_type: format!("{:?}",info.device_type),
                driver: info.driver,
                driver_info: info.driver_info,
                backend: format!("{:?}",info.backend),
            });
        }

        Self { devices }
    }

}

/// A single report of the capabilities of an Adapter.
///
/// Must be synchronized with the definition on tests/src/report.rs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[pyclass]
pub struct AdapterReport {

    /// Adapter name
    pub name: String,
    /// [`Backend`]-specific vendor ID of the adapter
    ///
    /// This generally is a 16-bit PCI vendor ID in the least significant bytes of this field.
    /// However, more significant bytes may be non-zero if the backend uses a different
    /// representation.
    ///
    /// * For [`Backend::Vulkan`], the [`VkPhysicalDeviceProperties::vendorID`] is used, which is
    ///     a superset of PCI IDs.
    ///
    /// [`VkPhysicalDeviceProperties::vendorID`]: https://registry.khronos.org/vulkan/specs/1.3-extensions/man/html/VkPhysicalDeviceProperties.html
    pub vendor: u32,
    /// [`Backend`]-specific device ID of the adapter
    ///
    ///
    /// This generally is a 16-bit PCI device ID in the least significant bytes of this field.
    /// However, more significant bytes may be non-zero if the backend uses a different
    /// representation.
    ///
    /// * For [`Backend::Vulkan`], the [`VkPhysicalDeviceProperties::deviceID`] is used, which is
    ///    a superset of PCI IDs.
    ///
    /// [`VkPhysicalDeviceProperties::deviceID`]: https://registry.khronos.org/vulkan/specs/1.3-extensions/man/html/VkPhysicalDeviceProperties.html
    pub device: u32,
    /// Type of device
    pub device_type: String,
    /// Driver name
    pub driver: String,
    /// Driver info
    pub driver_info: String,
    /// Backend used for device
    pub backend: String,
}

