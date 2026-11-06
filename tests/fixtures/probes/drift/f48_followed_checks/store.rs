use crate::{AuthenticatedUser, Fault};

pub struct Board {
    pub owner: u64,
    pub parent: Option<u64>,
}

pub struct Boards;

impl Boards {
    /// An associated function in another module.
    pub fn rename(caller: &AuthenticatedUser, id: u64) -> Result<(), Fault> {
        let board = load(id);
        ensure_owner(caller, &board)
    }
}

pub fn archive(caller: &AuthenticatedUser, id: u64) -> Result<(), Fault> {
    let board = root_of(load(id));
    ensure_owner(caller, &board)?;
    Ok(())
}

pub fn restore(caller: &AuthenticatedUser, id: u64) -> Result<(), Fault> {
    let board = root_of(load(id));
    ensure_owner(caller, &board)?;
    Ok(())
}

pub fn purge(_caller: &AuthenticatedUser, id: u64) -> Result<(), Fault> {
    let _board = root_of(load(id));
    Ok(())
}

/// The check: the caller must own the board.
fn ensure_owner(caller: &AuthenticatedUser, board: &Board) -> Result<(), Fault> {
    if caller.account != Some(board.owner) {
        return Err(Fault);
    }
    Ok(())
}

/// A recursive helper on the way.
fn root_of(board: Board) -> Board {
    match board.parent {
        Some(parent) => root_of(load(parent)),
        None => board,
    }
}

fn load(id: u64) -> Board {
    Board { owner: id, parent: None }
}
