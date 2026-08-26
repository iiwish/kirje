//! Reusable protocol adapters behind Kirje's agent-safe domain contract.

mod imap;
mod smtp;

pub use imap::PimalayaImapReader;
pub use smtp::LettreSmtpSender;
