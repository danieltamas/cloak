/// `cloak init` — initialise Cloak protection for a project.
pub mod init;

/// `cloak recover` — restore the vault key from a recovery key.
pub mod recover;

/// `cloak edit` — open the protected `.env` file in the user's editor.
pub mod edit;

/// `cloak run` — inject real environment variables and run a child process.
pub mod run;

/// `cloak peek` — show a side-by-side comparison of sandbox vs real values.
pub mod peek;

/// `cloak set` — add or update a single key-value pair in the vault.
pub mod set;

/// `cloak reveal` — temporarily replace a sandbox value with its real value.
pub mod reveal;

/// `cloak unprotect` — remove Cloak protection and restore the original `.env`.
pub mod unprotect;

/// `cloak status` — show the current protection status of the project.
pub mod status;

/// `cloak update` — self-update to the latest GitHub release.
pub mod update;
