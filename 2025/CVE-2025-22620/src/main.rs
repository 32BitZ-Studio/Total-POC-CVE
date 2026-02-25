fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo = gix::discover("has-executable")?;
    let mut index = repo.open_index()?;
    gix::worktree::state::checkout(
        &mut index,
        repo.work_dir().ok_or("need non-bare repo")?,
        gix_object::find::Never, // Can also use: repo.objects.clone()
        &gix::progress::Discard,
        &gix::progress::Discard,
        &Default::default(),
        Default::default(),
    )?;
    Ok(())
}
