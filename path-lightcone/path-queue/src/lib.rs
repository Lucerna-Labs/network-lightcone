//! PATHGATE (path-lightcone/PATHGATE-1-PRECOMMIT.md): the fail-closed kernel packet queue.
//! Recovered from Imperium commit 2bb1e8c (`imperium-net-host/src/queue.rs` and `queue_wire.rs`,
//! deleted by 1d58c98): one owned NETLINK_NETFILTER queue, full packet copies, FAIL_OPEN cleared,
//! every malformed message refused, each held packet consumed once. Mechanism only: it holds no
//! judgment. Changes from the original: `libc` replaced by `sys` (zero dependencies).

mod queue;
mod sys;
mod wire;

pub use queue::{KernelDisposition, PacketQueue};
pub use wire::HeldPacket;
