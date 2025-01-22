use std::path::PathBuf;
use winresource::WindowsResource;

fn main() {
    let res_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("res").join("eventmsgs.rc");
    WindowsResource::new()
        .set_resource_file(res_path.to_str().unwrap())
        .compile()
        .unwrap();
}
