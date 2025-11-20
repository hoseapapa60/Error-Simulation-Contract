(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INSUFFICIENT_FUNDS (err u101))
(define-constant ERR_INVALID_AMOUNT (err u102))
(define-constant ERR_ALREADY_EXISTS (err u103))
(define-constant ERR_NOT_FOUND (err u104))
(define-constant ERR_OVERFLOW (err u105))
(define-constant ERR_UNDERFLOW (err u106))
(define-constant ERR_DIVISION_BY_ZERO (err u107))
(define-constant ERR_REENTRANCY (err u108))
(define-constant ERR_PAUSED (err u109))
(define-constant ERR_EXPIRED (err u110))
(define-constant ERR_SNAPSHOT_LIMIT (err u200))
(define-constant ERR_SNAPSHOT_NOT_FOUND (err u201))

(define-data-var contract-owner principal tx-sender)
(define-data-var total-supply uint u1000000)
(define-data-var contract-paused bool false)
(define-data-var reentrancy-guard bool false)
(define-data-var withdrawal-fee uint u100)
(define-data-var max-withdrawal uint u10000)

(define-map user-balances principal uint)
(define-map user-deposits principal uint)
(define-map approved-operators principal bool)
(define-map withdrawal-requests 
  uint 
  {
    requester: principal,
    amount: uint,
    timestamp: uint,
    processed: bool
  })
(define-map vulnerable-storage principal uint)
(define-map access-levels principal uint)

(define-data-var next-withdrawal-id uint u1)
(define-data-var emergency-mode bool false)
(define-data-var last-update-block uint u0)
(define-data-var audit-entry-counter uint u0)
(define-data-var challenge-counter uint u0)
(define-data-var total-points-awarded uint u0)
(define-data-var max-snapshots-per-user uint u10)

(define-map audit-trail 
  uint 
  {
    caller: principal,
    function-name: (string-ascii 50),
    parameters: (string-ascii 200),
    success: bool,
    block-height: uint,
    vulnerability-type: (string-ascii 30)
  })

(define-map vulnerability-stats (string-ascii 30) uint)
(define-map caller-activity principal uint)

(define-map security-challenges
  uint
  {
    title: (string-ascii 100),
    description: (string-ascii 300),
    target-function: (string-ascii 50),
    difficulty: uint,
    points-reward: uint,
    active: bool,
    creator: principal
  })

(define-map user-progress
  {user: principal, challenge-id: uint}
  {
    completed: bool,
    attempts: uint,
    best-score: uint,
    completion-time: uint
  })

(define-map user-scores principal uint)
(define-map challenge-completions uint uint)
(define-map user-achievements principal (list 10 uint))

(define-map user-snapshot-count principal uint)
(define-map user-snapshot-next-id principal uint)
(define-map user-snapshots
  {user: principal, id: uint}
  {
    balance: uint,
    deposits: uint,
    access-level: uint,
    vuln-store: uint,
    timestamp: uint,
    note: (string-ascii 60)
  })

(define-private (log-vulnerability-attempt (function-name (string-ascii 50)) (parameters (string-ascii 200)) (success bool) (vuln-type (string-ascii 30)))
  (let 
    (
      (entry-id (var-get audit-entry-counter))
      (current-stats (default-to u0 (map-get? vulnerability-stats vuln-type)))
      (caller-count (default-to u0 (map-get? caller-activity tx-sender)))
    )
    (map-set audit-trail entry-id {
      caller: tx-sender,
      function-name: function-name,
      parameters: parameters,
      success: success,
      block-height: u1,
      vulnerability-type: vuln-type
    })
    (map-set vulnerability-stats vuln-type (+ current-stats u1))
    (map-set caller-activity tx-sender (+ caller-count u1))
    (var-set audit-entry-counter (+ entry-id u1))
    (ok entry-id)
  )
)

(define-public (create-snapshot (note (string-ascii 60)))
  (let 
    (
      (snapshot-count (default-to u0 (map-get? user-snapshot-count tx-sender)))
      (snapshot-id (default-to u1 (map-get? user-snapshot-next-id tx-sender)))
      (current-balance (default-to u0 (map-get? user-balances tx-sender)))
      (current-deposits (default-to u0 (map-get? user-deposits tx-sender)))
      (current-access (default-to u0 (map-get? access-levels tx-sender)))
      (current-vuln-store (default-to u0 (map-get? vulnerable-storage tx-sender)))
    )
    (asserts! (< snapshot-count (var-get max-snapshots-per-user)) ERR_SNAPSHOT_LIMIT)
    
    (map-set user-snapshots {user: tx-sender, id: snapshot-id} {
      balance: current-balance,
      deposits: current-deposits,
      access-level: current-access,
      vuln-store: current-vuln-store,
      timestamp: u1,
      note: note
    })
    
    (map-set user-snapshot-count tx-sender (+ snapshot-count u1))
    (map-set user-snapshot-next-id tx-sender (+ snapshot-id u1))
    (ok snapshot-id)
  )
)

(define-public (restore-snapshot (snapshot-id uint))
  (let 
    (
      (snapshot (unwrap! (map-get? user-snapshots {user: tx-sender, id: snapshot-id}) ERR_SNAPSHOT_NOT_FOUND))
    )
    (map-set user-balances tx-sender (get balance snapshot))
    (map-set user-deposits tx-sender (get deposits snapshot))
    (map-set access-levels tx-sender (get access-level snapshot))
    (map-set vulnerable-storage tx-sender (get vuln-store snapshot))
    (ok true)
  )
)

(define-public (delete-snapshot (snapshot-id uint))
  (let 
    (
      (snapshot (unwrap! (map-get? user-snapshots {user: tx-sender, id: snapshot-id}) ERR_SNAPSHOT_NOT_FOUND))
      (snapshot-count (default-to u0 (map-get? user-snapshot-count tx-sender)))
    )
    (map-delete user-snapshots {user: tx-sender, id: snapshot-id})
    (map-set user-snapshot-count tx-sender (if (> snapshot-count u0) (- snapshot-count u1) u0))
    (ok true)
  )
)

(define-public (create-security-challenge 
  (title (string-ascii 100)) 
  (description (string-ascii 300)) 
  (target-function (string-ascii 50)) 
  (difficulty uint) 
  (points-reward uint))
  (let 
    (
      (challenge-id (var-get challenge-counter))
    )
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (asserts! (and (> difficulty u0) (<= difficulty u5)) ERR_INVALID_AMOUNT)
    (asserts! (and (> points-reward u0) (<= points-reward u1000)) ERR_INVALID_AMOUNT)
    
    (map-set security-challenges challenge-id {
      title: title,
      description: description,
      target-function: target-function,
      difficulty: difficulty,
      points-reward: points-reward,
      active: true,
      creator: tx-sender
    })
    (map-set challenge-completions challenge-id u0)
    (var-set challenge-counter (+ challenge-id u1))
    (ok challenge-id)
  )
)

(define-public (attempt-challenge (challenge-id uint) (target-function-name (string-ascii 50)))
  (let 
    (
      (challenge (unwrap! (map-get? security-challenges challenge-id) ERR_NOT_FOUND))
      (progress-key {user: tx-sender, challenge-id: challenge-id})
      (current-progress (default-to {completed: false, attempts: u0, best-score: u0, completion-time: u0} 
                                   (map-get? user-progress progress-key)))
      (new-attempts (+ (get attempts current-progress) u1))
    )
    (asserts! (get active challenge) ERR_PAUSED)
    (asserts! (not (get completed current-progress)) ERR_ALREADY_EXISTS)
    (asserts! (is-eq (get target-function challenge) target-function-name) ERR_INVALID_AMOUNT)
    
    (map-set user-progress progress-key {
      completed: true,
      attempts: new-attempts,
      best-score: (get points-reward challenge),
      completion-time: u1
    })
    
    (map-set user-scores tx-sender 
      (+ (default-to u0 (map-get? user-scores tx-sender)) (get points-reward challenge)))
    
    (map-set challenge-completions challenge-id 
      (+ (default-to u0 (map-get? challenge-completions challenge-id)) u1))
    
    (var-set total-points-awarded 
      (+ (var-get total-points-awarded) (get points-reward challenge)))
    
    (ok (get points-reward challenge))
  )
)

(define-public (deactivate-challenge (challenge-id uint))
  (let 
    (
      (challenge (unwrap! (map-get? security-challenges challenge-id) ERR_NOT_FOUND))
    )
    (asserts! (or (is-eq tx-sender (var-get contract-owner)) 
                  (is-eq tx-sender (get creator challenge))) ERR_UNAUTHORIZED)
    
    (map-set security-challenges challenge-id 
      (merge challenge {active: false}))
    (ok true)
  )
)

(define-public (vulnerable-deposit (amount uint))
  (let 
    (
      (current-balance (default-to u0 (map-get? user-balances tx-sender)))
      (result (if (> amount u0)
        (begin
          (map-set user-balances tx-sender (+ current-balance amount))
          (var-set total-supply (+ (var-get total-supply) amount))
          (ok amount)
        )
        ERR_INVALID_AMOUNT
      ))
    )
    (unwrap-panic (log-vulnerability-attempt "vulnerable-deposit" "amount" (is-ok result) "validation"))
    result
  )
)

(define-public (overflow-vulnerable-add (a uint) (b uint))
  (let 
    (
      (result (ok (+ a b)))
    )
    (unwrap-panic (log-vulnerability-attempt "overflow-vulnerable-add" "a,b" (is-ok result) "arithmetic"))
    result
  )
)

(define-public (underflow-vulnerable-sub (a uint) (b uint))
  (let 
    (
      (result (ok (- a b)))
    )
    (unwrap-panic (log-vulnerability-attempt "underflow-vulnerable-sub" "a,b" (is-ok result) "arithmetic"))
    result
  )
)

(define-public (division-by-zero-vulnerable (a uint) (b uint))
  (let 
    (
      (result (ok (/ a b)))
    )
    (unwrap-panic (log-vulnerability-attempt "division-by-zero-vulnerable" "a,b" (is-ok result) "arithmetic"))
    result
  )
)

(define-public (reentrancy-vulnerable-withdraw (amount uint))
  (let 
    (
      (user-balance (default-to u0 (map-get? user-balances tx-sender)))
    )
    (if (>= user-balance amount)
      (begin
        (try! (stx-transfer? amount (as-contract tx-sender) tx-sender))
        (map-set user-balances tx-sender (- user-balance amount))
        (ok amount)
      )
      ERR_INSUFFICIENT_FUNDS
    )
  )
)

(define-public (access-control-vulnerable-admin-function (new-owner principal))
  (let 
    (
      (result (begin
        (var-set contract-owner new-owner)
        (ok true)
      ))
    )
    (unwrap-panic (log-vulnerability-attempt "access-control-vulnerable-admin-function" "new-owner" (is-ok result) "access-control"))
    result
  )
)

(define-public (integer-overflow-multiplication (a uint) (b uint))
  (ok (* a b))
)

(define-public (unchecked-external-call (recipient principal) (amount uint))
  (stx-transfer? amount tx-sender recipient)
)

(define-public (timestamp-manipulation-vulnerable (user-timestamp uint))
  (if (> user-timestamp u1000000)
    (ok true)
    (ok false)
  )
)

(define-public (logic-error-withdrawal (amount uint))
  (let 
    (
      (user-balance (default-to u0 (map-get? user-balances tx-sender)))
      (fee (/ (* amount (var-get withdrawal-fee)) u10000))
      (net-amount (- amount fee))
    )
    (if (> amount user-balance)
      ERR_INSUFFICIENT_FUNDS
      (begin
        (map-set user-balances tx-sender (- user-balance amount))
        (try! (stx-transfer? net-amount (as-contract tx-sender) tx-sender))
        (ok net-amount)
      )
    )
  )
)

(define-public (state-manipulation-attack (target-user principal) (new-balance uint))
  (let 
    (
      (result (begin
        (map-set user-balances target-user new-balance)
        (ok true)
      ))
    )
    (unwrap-panic (log-vulnerability-attempt "state-manipulation-attack" "target-user,new-balance" (is-ok result) "state-manipulation"))
    result
  )
)

(define-public (input-validation-vulnerable (user-input (string-ascii 100)))
  (let 
    (
      (input-length (len user-input))
    )
    (if (> input-length u0)
      (begin
        (map-set vulnerable-storage tx-sender input-length)
        (ok input-length)
      )
      ERR_INVALID_AMOUNT
    )
  )
)

(define-public (race-condition-vulnerable-update (new-value uint))
  (let 
    (
      (current-value (default-to u0 (map-get? vulnerable-storage tx-sender)))
    )
    (if (> new-value current-value)
      (begin
        (map-set vulnerable-storage tx-sender new-value)
        (var-set last-update-block u1)
        (ok new-value)
      )
      ERR_INVALID_AMOUNT
    )
  )
)

(define-public (front-running-vulnerable-trade (price uint))
  (let 
    (
      (user-balance (default-to u0 (map-get? user-balances tx-sender)))
    )
    (if (>= user-balance price)
      (begin
        (map-set user-balances tx-sender (- user-balance price))
        (map-set user-deposits tx-sender (+ (default-to u0 (map-get? user-deposits tx-sender)) u1))
        (ok true)
      )
      ERR_INSUFFICIENT_FUNDS
    )
  )
)

(define-public (privilege-escalation-vulnerability (target-level uint))
  (begin
    (map-set access-levels tx-sender target-level)
    (ok target-level)
  )
)

(define-public (replay-attack-vulnerable (nonce uint) (amount uint))
  (let 
    (
      (user-balance (default-to u0 (map-get? user-balances tx-sender)))
    )
    (if (>= user-balance amount)
      (begin
        (map-set user-balances tx-sender (- user-balance amount))
        (ok amount)
      )
      ERR_INSUFFICIENT_FUNDS
    )
  )
)

(define-public (denial-of-service-vulnerable)
  (ok u1000)
)

(define-public (emergency-pause)
  (begin
    (var-set contract-paused true)
    (var-set emergency-mode true)
    (ok true)
  )
)

(define-public (emergency-unpause)
  (if (is-eq tx-sender (var-get contract-owner))
    (begin
      (var-set contract-paused false)
      (var-set emergency-mode false)
      (ok true)
    )
    ERR_UNAUTHORIZED
  )
)

(define-public (secure-withdrawal (amount uint))
  (let 
    (
      (user-balance (default-to u0 (map-get? user-balances tx-sender)))
    )
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    (asserts! (not (var-get reentrancy-guard)) ERR_REENTRANCY)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    (asserts! (<= amount (var-get max-withdrawal)) ERR_INVALID_AMOUNT)
    (asserts! (>= user-balance amount) ERR_INSUFFICIENT_FUNDS)
    
    (var-set reentrancy-guard true)
    (map-set user-balances tx-sender (- user-balance amount))
    (try! (stx-transfer? amount (as-contract tx-sender) tx-sender))
    (var-set reentrancy-guard false)
    (ok amount)
  )
)

(define-public (secure-admin-function (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (asserts! (<= new-fee u1000) ERR_INVALID_AMOUNT)
    (var-set withdrawal-fee new-fee)
    (ok new-fee)
  )
)

(define-read-only (get-user-balance (user principal))
  (default-to u0 (map-get? user-balances user))
)

(define-read-only (get-contract-info)
  {
    owner: (var-get contract-owner),
    total-supply: (var-get total-supply),
    paused: (var-get contract-paused),
    emergency-mode: (var-get emergency-mode),
    withdrawal-fee: (var-get withdrawal-fee),
    max-withdrawal: (var-get max-withdrawal)
  }
)

(define-read-only (check-vulnerability-status)
  {
    reentrancy-guard: (var-get reentrancy-guard),
    last-update: (var-get last-update-block),
    next-withdrawal-id: (var-get next-withdrawal-id)
  }
)

(define-read-only (get-audit-entry (entry-id uint))
  (map-get? audit-trail entry-id)
)

(define-read-only (get-vulnerability-stats (vuln-type (string-ascii 30)))
  (default-to u0 (map-get? vulnerability-stats vuln-type))
)

(define-read-only (get-caller-activity (caller principal))
  (default-to u0 (map-get? caller-activity caller))
)

(define-read-only (get-total-audit-entries)
  (var-get audit-entry-counter)
)

(define-read-only (get-audit-summary)
  {
    total-entries: (var-get audit-entry-counter),
    arithmetic-attacks: (default-to u0 (map-get? vulnerability-stats "arithmetic")),
    access-control-attacks: (default-to u0 (map-get? vulnerability-stats "access-control")),
    state-manipulation-attacks: (default-to u0 (map-get? vulnerability-stats "state-manipulation")),
    validation-attacks: (default-to u0 (map-get? vulnerability-stats "validation"))
  }
)

(define-read-only (get-challenge (challenge-id uint))
  (map-get? security-challenges challenge-id)
)

(define-read-only (get-user-score (user principal))
  (default-to u0 (map-get? user-scores user))
)

(define-read-only (get-user-progress (user principal) (challenge-id uint))
  (map-get? user-progress {user: user, challenge-id: challenge-id})
)

(define-read-only (get-challenge-stats (challenge-id uint))
  (default-to u0 (map-get? challenge-completions challenge-id))
)

(define-read-only (get-total-challenges)
  (var-get challenge-counter)
)

(define-read-only (get-challenge-leaderboard)
  {
    total-challenges: (var-get challenge-counter),
    total-points-awarded: (var-get total-points-awarded),
    active-challenges: u0
  }
)

(define-read-only (get-user-achievements (user principal))
  (default-to (list) (map-get? user-achievements user))
)

(define-read-only (is-challenge-completed (user principal) (challenge-id uint))
  (match (map-get? user-progress {user: user, challenge-id: challenge-id})
    progress (get completed progress)
    false
  )
)

(define-read-only (get-snapshot (user principal) (snapshot-id uint))
  (map-get? user-snapshots {user: user, id: snapshot-id})
)

(define-read-only (get-user-snapshot-count (user principal))
  (default-to u0 (map-get? user-snapshot-count user))
)

(define-read-only (get-max-snapshots)
  (var-get max-snapshots-per-user)
)

(define-read-only (list-user-snapshots (user principal))
  {
    total-snapshots: (default-to u0 (map-get? user-snapshot-count user)),
    next-id: (default-to u1 (map-get? user-snapshot-next-id user)),
    max-allowed: (var-get max-snapshots-per-user)
  }
)
