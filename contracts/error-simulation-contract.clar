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

(define-public (vulnerable-deposit (amount uint))
  (let 
    (
      (current-balance (default-to u0 (map-get? user-balances tx-sender)))
    )
    (if (> amount u0)
      (begin
        (map-set user-balances tx-sender (+ current-balance amount))
        (var-set total-supply (+ (var-get total-supply) amount))
        (ok amount)
      )
      ERR_INVALID_AMOUNT
    )
  )
)

(define-public (overflow-vulnerable-add (a uint) (b uint))
  (ok (+ a b))
)

(define-public (underflow-vulnerable-sub (a uint) (b uint))
  (ok (- a b))
)

(define-public (division-by-zero-vulnerable (a uint) (b uint))
  (ok (/ a b))
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
  (begin
    (var-set contract-owner new-owner)
    (ok true)
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
  (begin
    (map-set user-balances target-user new-balance)
    (ok true)
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
