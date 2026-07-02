use cargo_metadata::MetadataCommand;

fn main() {
    let md = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("cargo metadata");
    let pkg = md
        .packages
        .iter()
        .find(|p| p.name.as_str() == "radar-ebpf")
        .expect("radar-ebpf package not found");
    let root_dir = pkg
        .manifest_path
        .parent()
        .expect("manifest parent")
        .as_str();
    let ebpf = aya_build::Package {
        name: pkg.name.as_str(),
        root_dir,
        no_default_features: false,
        features: &[],
    };
    aya_build::build_ebpf([ebpf], aya_build::Toolchain::default()).expect("build_ebpf failed");
}
