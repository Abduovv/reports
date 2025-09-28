# Disclaimer

---

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource, and expertise bound effort where we try to find as many vulnerabilities as possible. We cannot guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs, and on-chain monitoring are strongly recommended.

---

# Summary of Findings

**Assumption**: The `game_server` (authority) is a fully trusted backend that won't misuse instructions (e.g., no repeated/untimely calls). Including the `game_server` public key in the `game_session` PDA seeds ensures uniqueness per creator, mitigating DoS risks from session ID collisions.

| ID   | Title                                                                                  |
| ---- | -------------------------------------------------------------------------------------- |
| H-01 | Non-unique PDA Seeds for `game_session` Leading to DoS Risk                            |
| H-02 | `vault_token_account` uses `init` can lead to DoS Attack                               |
| H-03 | `vault` account initialized with `space = 0` — risk of deletion                        |
| H-04 | Insufficient Validation and Ordering of `remaining_accounts` in `refund_wager_handler` |
| M-01 | Oversized account allocation for `game_session`                                        |
| M-02 | Lack of validation allows users to join multiple times                                 |
| M-03 | Unchecked Underflow in `add_kill` Reducing Player Spawns                               |
| M-04 | Potential Panic on Slicing Team Players                                                |
| L-01 | Unbounded `session_id` string in `GameSession`                                         |
| L-02 | Missing validation on `session_bet`                                                    |
| L-03 | Marking Session as `Completed` Even if Refunds Fail Mid-Loop                           |
| L-04 | Truncation in Earnings Calculation                                                     |
| I-01 | Unnecessary and Unvalidated `game_server` Account                                      |
| I-02 | Unnecessary `vault_token_bump` Field in `GameSession`                                  |

---

# Risk Classification

**Audit Scope**  
All the programs in `/programs/wager-program`:

- lib.rs
- create_game_session.rs
- distribute_winnings.rs
- join_user.rs
- mod.rs
- pay_to_spawn.rs
- record_kill.rs
- refund_wager.rs
- state.rs
- utils.rs
- errors.rs

---

## Findings

---

## High Findings

---

### [H-01] Non-unique PDA Seeds for `game_session` Leading to DoS Risk

PoC file: `pocs_wager/H-01_pda_front_run_dos.test.ts`

#### Description

The `create_game_session` instruction derives the `game_session` PDA using only `[b"game_session", session_id.as_bytes()]`, with no guarantee of `session_id` uniqueness per creator. This allows an attacker to front-run by creating a PDA with the same `session_id` as a legitimate game server, causing legitimate calls to fail with `AccountAlreadyInitialized`, resulting in a denial-of-service.

#### Issue in Code

```rust
#[derive(Accounts)]
#[instruction(session_id: String)]
pub struct CreateGameSession<'info> {
    #[account(mut)]
    pub game_server: Signer<'info>,

    #[account(
        init,
        payer = game_server,
        space = 8 + 4 + 10 + 32 + 8 + 1 + (2 * (32 * 5 + 16 * 5 + 16 * 5 + 8)) + 1 + 8 + 1 + 1 + 1,
        seeds = [b"game_session", session_id.as_bytes()],
        bump
    )]
    pub game_session: Account<'info, GameSession>,
    ...
}
```

#### Impact

- **PDA Front-running / DoS**: An attacker can preemptively create a PDA with a chosen `session_id`, causing legitimate `create_game_session` calls to fail.
- **Platform Disruption**: Prevents legitimate game sessions from being created, undermining platform functionality and user trust.

#### Recommendation

Include the `game_server` public key in the PDA seeds to ensure uniqueness per creator, preventing front-running:

```rust
#[derive(Accounts)]
#[instruction(session_id: String)]
pub struct CreateGameSession<'info> {
    #[account(mut)]
    pub game_server: Signer<'info>,

    #[account(
        init,
        payer = game_server,
        space = 8 + 4 + 10 + 32 + 8 + 1 + (2 * (32 * 5 + 16 * 5 + 16 * 5 + 8)) + 1 + 8 + 1 + 1 + 1,
        seeds = [b"game_session", game_server.key().as_ref(), session_id.as_bytes()],
        bump
    )]
    pub game_session: Account<'info, GameSession>,
    // ... other accounts
}
```

---

### [H-02] `vault_token_account` uses `init` can lead to DoS Attack

PoC file: `pocs_wager/H-02_vault_ata_init_dos.test.ts`

#### Description

The `vault_token_account` in `create_game_session` is created with `init`, requiring the associated token account (ATA) to not exist. An attacker can pre-create the ATA for the `(mint, vault)` pair, causing the legitimate transaction to fail with `AccountAlreadyInitialized`.

#### Issue in Code

```rust
#[account(
    init,
    payer = game_server,
    associated_token::mint = mint,
    associated_token::authority = vault,
)]
pub vault_token_account: Account<'info, TokenAccount>,
```

#### Impact

- **Front-running / DoS**: An attacker can create the ATA first, causing legitimate `create_game_session` calls to fail.
- **Broken flows**: Instructions expecting the ATA to be created by this transaction will revert, halting session creation.

#### Recommendation

Use `init_if_needed` to allow the instruction to proceed whether the ATA exists or not:

```rust
#[account(
    init_if_needed,
    payer = game_server,
    associated_token::mint = mint,
    associated_token::authority = vault,
)]
pub vault_token_account: Account<'info, TokenAccount>,
```

---

### [H-03] `vault` account initialized with `space = 0` — risk of deletion

PoC file: `pocs_wager/H-03_vault_space_zero_rent_risk.test.ts`

#### Description

The `vault` PDA in `create_game_session` is initialized with `space = 0`, creating an account with no discriminator or data and no rent-exempt balance. Such accounts can be closed if their lamports drop below the rent-exemption threshold, breaking assumptions about the vault’s persistence.

#### Issue in Code

```rust
#[account(
    init,
    payer = game_server,
    space = 0,
    seeds = [b"vault", session_id.as_bytes()],
    bump
)]
pub vault: AccountInfo<'info>,
```

#### Impact

- **Account deletion risk**: The vault can be closed if its balance falls below the rent-exemption threshold, potentially losing funds.
- **Inconsistent state**: Program logic relying on a persistent vault (e.g., for token transfers) will fail if the account is deleted.

#### Recommendation

Allocate minimal space for rent exemption and use a typed account for clarity:

```rust
#[account(
    init,
    payer = game_server,
    space = 8, // Minimal space for rent-exemption
    seeds = [b"vault", session_id.as_bytes()],
    bump
)]
pub vault: SystemAccount<'info>,
```

---

### [H-04] Incorrect Payout Logic in `distribute_all_winnings_handler`

PoC file: `pocs_wager/H-06_incorrect_payout_logic_all_winnings.test.ts`

#### Description

The `distribute_all_winnings_handler` function calculates `total_pot` but uses a fixed `winning_amount = session_bet * 2` for each winner, ignoring the actual `total_pot`. This can lead to incorrect distributions, either overpaying or underpaying winners, and potentially leaving funds stuck in the vault.

#### Issue in Code

```rust
// Calculate total pot (sum of both teams' bets)
let total_pot = game_session.session_bet * players_per_team as u64 * 2;
msg!("Total pot calculated: {}", total_pot);

let winning_amount = game_session.session_bet * 2;
msg!("Winning amount calculated: {}", winning_amount);
```

#### Impact

- For `players_per_team = 3`, `total_pot = session_bet * 3 * 2 = 6 * session_bet`. Each winner gets `session_bet * 2`, so total payout = `3 * session_bet * 2 = 6 * session_bet` (correct).
- For `players_per_team = 1`, `total_pot = session_bet * 1 * 2 = 2 * session_bet`. Each winner gets `session_bet * 2`, so total payout = `2 * session_bet` (correct).
- However, if `total_pot` is not evenly divisible by the number of winners, or if additional funds (e.g., from `pay_to_spawn`) are in the vault, the fixed multiplier leads to underpayment or overpayment, leaving funds stuck or causing transaction failures.
- The logic assumes equal team sizes and bets, which may not hold if teams are uneven or additional bets are added.

#### Recommendation

Distribute the `total_pot` evenly among the winners based on the actual vault balance or calculated pot:

```rust
let total_pot = game_session.session_bet * players_per_team as u64 * 2;
require!(
    ctx.accounts.vault_token_account.amount >= total_pot,
    WagerError::InsufficientVaultBalance
);
let winning_amount = total_pot / players_per_team as u64;
```

---

### [H-05] Insufficient Validation and Ordering of `remaining_accounts` in `refund_wager_handler`

PoC file: `pocs_wager/H-07_unvalidated_remaining_accounts_refund.test.ts`

#### Description

The `refund_wager_handler` function assumes `remaining_accounts` are provided as `(player, token_account)` pairs but only checks that the list is non-empty and contains an even number of accounts. It does not validate that the provided accounts match the registered players in `game_session.get_all_players()` or ensure correct ordering, allowing attackers to supply arbitrary accounts or manipulate the order to redirect refunds.

#### Issue in Code

```rust
require!(
    !ctx.remaining_accounts.is_empty(),
    WagerError::InvalidRemainingAccounts
);

require!(
    ctx.remaining_accounts.len() % 2 == 0,
    WagerError::InvalidRemainingAccounts
);

let player_index = ctx
    .remaining_accounts
    .iter()
    .step_by(2)
    .position(|acc| acc.key() == player)
    .ok_or(WagerError::InvalidPlayer)?;
```

#### Impact

- Attackers can provide malicious `(attacker_account, attacker_token_account)` pairs or reorder accounts to redirect refunds intended for legitimate players.
- Legitimate players may lose their entitled refunds, leading to financial loss.
- The reliance on manual iteration and minimal checks makes the function vulnerable to manipulation.

#### Recommendation

Validate that each player account in `remaining_accounts` matches a registered player in `game_session.get_all_players()` and ensure the corresponding token account is owned by that player, with correct ordering:

```rust
let players = game_session.get_all_players();
require!(
    ctx.remaining_accounts.len() == players.len() * 2,
    WagerError::InvalidRemainingAccounts
);

for (i, player) in players.iter().enumerate() {
    if *player == Pubkey::default() {
        continue;
    }
    let player_account = &ctx.remaining_accounts[i * 2];
    let player_token_account_info = &ctx.remaining_accounts[i * 2 + 1];
    require!(
        player_account.key() == *player,
        WagerError::InvalidPlayer
    );
    let player_token_account = Account::<TokenAccount>::try_from(player_token_account_info)?;
    require!(
        player_token_account.owner == player_account.key(),
        WagerError::InvalidPlayerTokenAccount
    );
    require!(
        player_token_account.mint == TOKEN_ID,
        WagerError::InvalidTokenMint
    );
    // Proceed with transfer logic
}
```

---

## Medium Findings

---

### [M-01] Oversized account allocation for `game_session`

PoC file: `pocs_wager/M-01_oversized_game_session_space.test.ts`

#### Description

The `space` allocated for the `game_session` account is larger than what the struct actually requires. This wastes SOL in rent and makes deployment less efficient.

#### Issue in Code

```rust
#[account(
    init,
    payer = game_server,
    space = 8 + 4 + 10 + 32 + 8 + 1 + (2 * (32 * 5 + 16 * 5 + 16 * 5 + 8)) + 1 + 8 + 1 + 1 + 1, // ≈ 731 bytes
    seeds = [b"game_session", session_id.as_bytes()],
    bump
)]
pub game_session: Account<'info, GameSession>,
```

#### Impact

- **Increased rent cost**: Extra unused bytes increase the lamports required to keep the account alive.
- **Inefficient storage**: Repeated creation of oversized accounts leads to unnecessary resource consumption.

#### Recommendation

Recalculate `space` precisely based on the struct’s fields. With `session_id` capped at 32 bytes, the total required space is:

```rust
8   // discriminator
+ 4 + 32  // session_id
+ 32      // authority
+ 8       // session_bet
+ 1       // game_mode
+ (32*5 + 8 + 2*5 + 2*5)  // team_a
+ (32*5 + 8 + 2*5 + 2*5)  // team_b
+ 1       // game_status
+ 8       // created_at
+ 1 + 1   // bump + vault_bump
= 411 bytes
```

Update the account definition:

```rust
space = 411
```

---

### [M-02] Lack of validation allows users to join multiple times

PoC file: `pocs_wager/M-02_join_multiple_times_allowed.test.ts`

#### Description

The `join_user_handler` instruction does not check whether a user has already joined the session. As a result, the same user can join multiple times in the same team or across different teams, breaking the integrity of the game session and potentially allowing abuse.

#### Issue in Code

```rust
pub fn join_user_handler(
    ctx: Context<JoinUser>,
    _session_id: String,
    team: u8,
) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;

    // Validate game status
    require!(
        game_session.status == GameStatus::WaitingForPlayers,
        WagerError::InvalidGameState
    );
}
```

#### Impact

- One user can occupy multiple slots, preventing fair participation.
- If rewards or bets are tied to participant count, the attacker can manipulate payouts.

#### Recommendation

Enforce user uniqueness by checking if the user is already in any team:

```rust
let user = ctx.accounts.user.key();
let already_in_a = game_session.team_a.players.iter().any(|p| *p == user);
let already_in_b = game_session.team_b.players.iter().any(|p| *p == user);
require!(!already_in_a && !already_in_b, WagerError::AlreadyJoined);
```

---

### [M-03] Unchecked Underflow in `add_kill` Reducing Player Spawns

PoC file: `pocs_wager/M-03_unchecked_underflow_add_kill.test.ts`

#### Description

In `add_kill`, the code decrements a victim’s `player_spawns` without ensuring it is greater than zero. If `player_spawns` is already zero, this subtraction can underflow (wrapping to `u16::MAX`) or panic at runtime, enabling an attacker to manipulate a victim’s spawn count for unintended behavior or DOS via panic.

#### Issue in Code

```rust
match victim_team {
    0 => self.team_a.player_spawns[victim_player_index] -= 1,
    1 => self.team_b.player_spawns[victim_player_index] -= 1,
    _ => return Err(error!(WagerError::InvalidTeam)),
}
```

#### Impact

- **State Manipulation**: Underflow sets `player_spawns` to `u16::MAX`, allowing infinite spawns.
- **DoS**: Panics in debug builds cause transaction failures, stalling gameplay.

#### Recommendation

Before decrementing, check that `player_spawns > 0`. Use `checked_sub(1)` or `saturating_sub(1)` and return an error if underflow would occur:

```rust
require!(
    self.team_a.player_spawns[victim_player_index] > 0,
    WagerError::NoSpawnsRemaining
);
self.team_a.player_spawns[victim_player_index] = self.team_a.player_spawns[victim_player_index].saturating_sub(1);
```

---

### [M-04] Potential Panic on Slicing Team Players

PoC file: `pocs_wager/M-04_potential_panic_slicing.test.ts`

#### Description

In `distribute_all_winnings_handler`, the code slices the player arrays without bounds checking: `&game_session.team_a.players[0..players_per_team]` and similarly for team B. If `players_per_team` exceeds the length of `team_a.players` or `team_b.players`, this will panic and abort the program, resulting in a Denial of Service.

#### Issue in Code

```rust
let winning_players = if winning_team == 0 {
    &game_session.team_a.players[0..players_per_team]
} else {
    &game_session.team_b.players[0..players_per_team]
};
```

#### Impact

- **DoS**: Panics abort transactions, preventing payouts and stalling the session.
- **Gameplay Disruption**: Affects game finalization and player rewards.

#### Recommendation

Validate that `players_per_team <= team_a.players.len()` and `<= team_b.players.len()` before slicing. Use `get(0..players_per_team)` or `checked_sub` to avoid panics:

```rust
require!(
    players_per_team <= game_session.team_a.players.len() && players_per_team <= game_session.team_b.players.len(),
    WagerError::InvalidPlayerCount
);
```

---

## Low Findings

---

### [L-01] Unbounded `session_id` string in `GameSession`

#### Description

The `session_id` field in the `GameSession` struct is stored as a `String` without a defined maximum length. In Anchor, `String` requires explicit space reservation, and without a cap, malicious users can provide excessively large values, increasing account size and rent costs or causing transaction failures.

#### Issue in Code

```rust
#[account]
pub struct GameSession {
    pub session_id: String,  // Unique identifier for the game
    pub authority: Pubkey,
    pub session_bet: u64,
    pub game_mode: GameMode,
    pub team_a: Team,
    pub team_b: Team,
    pub status: GameStatus,
    pub created_at: i64,
    pub bump: u8,
    pub vault_bump: u8,
    pub vault_token_bump: u8,
}
```

#### Impact

- **Excessive allocation**: Large `session_id` values increase the `GameSession` account size, leading to higher rent costs.
- **DoS vector**: Transactions may fail if the account size exceeds practical limits or available lamports.
- **Indexing issues**: Unbounded strings may cause off-chain lookup or consistency issues, complicating session management.

#### Recommendation

Define a maximum length for `session_id` (e.g., `MAX_SESSION_ID_LEN = 32`) and validate it in `create_game_session_handler`:

```rust
const MAX_SESSION_ID_LEN: usize = 32;

pub fn create_game_session_handler(
    ctx: Context<CreateGameSession>,
    session_id: String,
    bet_amount: u64,
    game_mode: GameMode,
) -> Result<()> {
    require!(
        session_id.len() <= MAX_SESSION_ID_LEN,
        WagerError::SessionIdTooLong
    );
    // Rest of the function
}
```

Adjust the `space` calculation in the `GameSession` account to reserve `4 + MAX_SESSION_ID_LEN` bytes for the `String`:

```rust
#[account(
    init,
    payer = game_server,
    space = 411, // Updated space
    seeds = [b"game_session", game_server.key().as_ref(), session_id.as_bytes()],
    bump
)]
pub game_session: Account<'info, GameSession>,
```

---

### [L-02] Missing validation on `session_bet`

#### Description

The `session_bet` field in `GameSession` is set via the `bet_amount` parameter in `create_game_session` without validation. Allowing values like `0` or `u64::MAX` can lead to meaningless game sessions or arithmetic issues in payout calculations.

#### Issue in Code

```rust
#[account]
pub struct GameSession {
    pub session_id: String,
    pub authority: Pubkey,
    pub session_bet: u64,    // Required bet amount per player
    pub game_mode: GameMode,
    pub team_a: Team,
    pub team_b: Team,
    pub status: GameStatus,
    pub created_at: i64,
    pub bump: u8,
    pub vault_bump: u8,
    pub vault_token_bump: u8,
}
```

#### Impact

- A `session_bet` of `0` allows sessions with no stakes, undermining the game’s purpose and potentially enabling spam sessions.
- A `session_bet` of `u64::MAX` could cause arithmetic overflows or unexpected behavior in payout calculations (e.g., in `distribute_all_winnings_handler`).
- While vault balance checks may prevent some issues, the lack of upfront validation risks inconsistent game logic.

#### Recommendation

Enforce reasonable bounds for `session_bet` in `create_game_session_handler`:

```rust
const MAX_ALLOWED_BET: u64 = 1_000_000_000; // Example max bet (1B lamports)

pub fn create_game_session_handler(
    ctx: Context<CreateGameSession>,
    session_id: String,
    bet_amount: u64,
    game_mode: GameMode,
) -> Result<()> {
    require!(bet_amount > 0, WagerError::InvalidBetAmount);
    require!(bet_amount <= MAX_ALLOWED_BET, WagerError::BetAmountTooHigh);
    // Rest of the function
}
```

---

### [L-03] Marking Session as `Completed` Even if Refunds Fail Mid-Loop

#### Description

The `refund_wager_handler` function marks the `game_session` as `Completed` after the refund loop, even if some transfers fail (e.g., due to insufficient vault balance). This prevents subsequent attempts to correct or complete the refunds, leaving the session in an inconsistent state.

#### Issue in Code

```rust
let game_session = &mut ctx.accounts.game_session;
game_session.status = GameStatus::Completed;
```

#### Impact

- If a transfer fails mid-loop (e.g., due to insufficient funds in `vault_token_account`), some players may not receive refunds, but the session is still marked `Completed`.
- This prevents further refund attempts, potentially leaving funds stuck in the vault or players uncompensated.
- The issue risks user dissatisfaction and financial discrepancies.

#### Recommendation

Only mark the session as `Completed` after all refunds succeed. Check the vault balance before starting transfers and handle failures gracefully:

```rust
let players = game_session.get_all_players();
let total_refunded = players.iter().filter(|p| **p != Pubkey::default()).count() as u64 * game_session.session_bet;
require!(
    ctx.accounts.vault_token_account.amount >= total_refunded,
    WagerError::InsufficientVaultBalance
);

// Perform transfers in loop
for player in players {
    // Transfer logic as existing
}

// Only mark as Completed if all transfers succeed
game_session.status = GameStatus::Completed;
```

---

### [L-04] Truncation in Earnings Calculation

#### Description

Dividing by 10 without ensuring `session_bet` is a multiple of 10 can truncate fractional earnings, which may lead to small rounding losses for players.

#### Issue in Code

```rust
let earnings = kills_and_spawns as u64 * game_session.session_bet / 10;
```

#### Impact

- **Rounding losses**: Players lose small amounts due to truncation.
- **Vault retention**: Remainders stay in the vault, potentially causing disputes.

#### Recommendation

Document the rounding behavior or require that `session_bet % 10 == 0` at session creation. Alternatively, implement a mechanism to distribute remainders fairly:

```rust
require!(
    game_session.session_bet % 10 == 0,
    WagerError::InvalidBetAmount
);
```

---

## Informational Findings

---

### [I-01] Unnecessary and Unvalidated `game_server` Account

#### Description

The `JoinUser` instruction includes a `game_server` account that is neither validated nor used for authorization, making it unnecessary.

#### Issue in Code

```rust
#[derive(Accounts)]
#[instruction(session_id: String)]
pub struct JoinUser<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    /// CHECK: Game server authority
    pub game_server: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [b"game_session", session_id.as_bytes()],
        bump = game_session.bump,
    )]
    pub game_session: Account<'info, GameSession>,
}
```

#### Impact

- Unnecessary accounts increase transaction complexity and cost.
- Lack of validation could lead to confusion or future vulnerabilities if the account is mistakenly assumed to be authoritative.

#### Recommendation

Remove the `game_server` account from the `JoinUser` struct:

```rust
#[derive(Accounts)]
#[instruction(session_id: String)]
pub struct JoinUser<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"game_session", session_id.as_bytes()],
        bump = game_session.bump,
    )]
    pub game_session: Account<'info, GameSession>,
    // Other accounts...
}
```

---

### [I-02] Unnecessary `vault_token_bump` Field in `GameSession`

#### Description

The `GameSession` struct includes a `vault_token_bump` field to store the bump seed for the vault’s associated token account (ATA). However, ATAs do not use bumps, as their addresses are deterministically derived from the mint and authority. Storing this field is unnecessary and increases the account size without providing any functional benefit.

#### Issue in Code

```rust
#[account]
pub struct GameSession {
    pub session_id: String,
    pub authority: Pubkey,
    pub session_bet: u64,
    pub game_mode: GameMode,
    pub team_a: Team,
    pub team_b: Team,
    pub status: GameStatus,
    pub created_at: i64,
    pub bump: u8,
    pub vault_bump: u8,
    pub vault_token_bump: u8,
}
```

#### Impact

- **Increased storage**: The `vault_token_bump` field adds an unnecessary 1 byte to the `GameSession` account, increasing rent costs slightly.
- **Code confusion**: The presence of an unused field may confuse developers or auditors, potentially leading to incorrect assumptions about the vault token account’s derivation.
- **No functional impact**: Since ATAs do not require bumps, the field is not used in any program logic, making it a minor inefficiency.

#### Recommendation

Remove the `vault_token_bump` field from the `GameSession` struct and update the `space` calculation accordingly:

```rust
#[account]
pub struct GameSession {
    pub session_id: String,
    pub authority: Pubkey,
    pub session_bet: u64,
    pub game_mode: GameMode,
    pub team_a: Team,
    pub team_b: Team,
    pub status: GameStatus,
    pub created_at: i64,
    pub bump: u8,
    pub vault_bump: u8,
}
```

Recalculate the `space` for `GameSession` (assuming `session_id` is capped at 32 bytes):

```rust
8   // discriminator
+ 4 + 32  // session_id
+ 32      // authority
+ 8       // session_bet
+ 1       // game_mode
+ (32*5 + 8 + 2*5 + 2*5)  // team_a
+ (32*5 + 8 + 2*5 + 2*5)  // team_b
+ 1       // game_status
+ 8       // created_at
+ 1 + 1   // bump + vault_bump
= 411 bytes
```

Update the account definition:

```rust
#[account(
    init,
    payer = game_server,
    space = 411,
    seeds = [b"game_session", game_server.key().as_ref(), session_id.as_bytes()],
    bump
)]
pub game_session: Account<'info, GameSession>,
```

---