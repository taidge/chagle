use anyhow::Result;
use vergen::EmitBuilder;

fn main() -> Result<()> {
    if let Err(e) = EmitBuilder::builder()
        .all_build()
        .all_cargo()
        .git_describe(true, true, None)
        .git_sha(false)
        .git_commit_timestamp()
        .git_branch()
        .emit()
    {
        eprintln!("vergen error: {:?}", e);
        // Fallback without git
        EmitBuilder::builder()
            .all_build()
            .all_cargo()
            .emit()?;
    }
    Ok(())
}
