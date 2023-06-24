use winresource::WindowsResource;

fn main() {
    WindowsResource::new()
        .set_resource_file("res/eventmsgs.rc")
        .compile()
        .unwrap();
}
