mod discovery;
mod native;
pub mod registry;
mod scan;

pub use discovery::discover;
pub use native::native_uninstall;
pub use registry::{
    delete_registry_key, export_registry_key, import_registry_file, key_exists, value_count,
};
pub use scan::{path_size, scan_orphans, scan_residue};
