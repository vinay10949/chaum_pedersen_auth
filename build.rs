fn main() {
    ::capnpc::CompilerCommand::new()
        .file("schemas/auth.capnp")
        .run()
        .expect("compiling schema");
}
