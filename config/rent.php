<?php
// config/rent.php
//
// Rent obligation, arrears and receipt helpers for Phase 3.
//
// Business rules (approved):
// - Full rent only; no partial payments.
// - Each tenant has an individual contractual due day.
// - Cash and EFT only. Cash is recorded by staff; EFT is verified against the
//   bank before it is marked paid.
// - Receipts are sequential and database-backed. They are never random,
//   renumbered or silently overwritten.

require_once __DIR__ . '/security.php';

const RENT_UNPAID_STATUSES = ['Pending', 'Overdue', 'Submitted', 'PendingVerification', 'Rejected', 'Reversed'];

/**
 * The due date for a rent obligation.
 *
 * @param string $month    Any date in the billing month (usually Y-m-01).
 * @param int    $dueDay   Contractual day of month (1-31), clamped to the
 *                         month's length when a month is shorter.
 */
function rent_due_date_for(string $month, int $dueDay): string
{
    $timestamp = strtotime($month);
    if ($timestamp === false) {
        $timestamp = time();
    }

    $year = (int) date('Y', $timestamp);
    $monthNumber = (int) date('n', $timestamp);
    $daysInMonth = (int) date('t', $timestamp);

    $day = max(1, min(31, $dueDay));
    if ($day > $daysInMonth) {
        $day = $daysInMonth;
    }

    return sprintf('%04d-%02d-%02d', $year, $monthNumber, $day);
}

/**
 * Generate monthly rent obligations from the active lease terms.
 *
 * Existing rows for a month are never overwritten, so this is safe to call
 * again after a lease amendment. Returns the number of rows created.
 */
function rent_generate_obligations(
    PDO $conn,
    int $tenantId,
    int $unitId,
    ?int $leaseId,
    string $startDate,
    string $endDate,
    float $monthlyRent,
    int $dueDay = 1
): int {
    if ($monthlyRent <= 0) {
        return 0;
    }

    $start = strtotime($startDate);
    $end = strtotime($endDate);
    if ($start === false || $end === false || $end < $start) {
        return 0;
    }

    $exists = $conn->prepare(
        'SELECT id, due_date FROM rent_records WHERE tenant_id = :tenant_id AND month_for = :month LIMIT 1'
    );
    $insert = $conn->prepare(
        "INSERT INTO rent_records (tenant_id, unit_id, lease_id, month_for, due_date, amount, status)
         VALUES (:tenant_id, :unit_id, :lease_id, :month, :due_date, :amount, 'Pending')"
    );
    $backfillDue = $conn->prepare(
        'UPDATE rent_records SET due_date = :due_date WHERE id = :id AND due_date IS NULL'
    );

    $created = 0;
    $cursor = strtotime(date('Y-m-01', $start));
    $lastMonth = strtotime(date('Y-m-01', $end));

    while ($cursor !== false && $cursor <= $lastMonth) {
        $month = date('Y-m-01', $cursor);
        $dueDate = rent_due_date_for($month, $dueDay);

        $exists->execute([':tenant_id' => $tenantId, ':month' => $month]);
        $existing = $exists->fetch(PDO::FETCH_ASSOC);

        if ($existing === false) {
            $insert->execute([
                ':tenant_id' => $tenantId,
                ':unit_id' => $unitId,
                ':lease_id' => $leaseId,
                ':month' => $month,
                ':due_date' => $dueDate,
                ':amount' => $monthlyRent,
            ]);
            $created++;
        } elseif (empty($existing['due_date'])) {
            $backfillDue->execute([':due_date' => $dueDate, ':id' => (int) $existing['id']]);
        }

        $cursor = strtotime('+1 month', $cursor);
    }

    return $created;
}

/**
 * Return the next receipt number, using a locked per-year sequence.
 *
 * MUST be called inside a database transaction. The row lock serialises
 * concurrent issuers so two payments can never receive the same number.
 */
function rent_next_receipt_number(PDO $conn): string
{
    $year = (int) date('Y');

    $conn->prepare(
        'INSERT INTO receipt_sequences (year, last_number) VALUES (:year, 1)
         ON DUPLICATE KEY UPDATE last_number = last_number + 1'
    )->execute([':year' => $year]);

    $stmt = $conn->prepare('SELECT last_number FROM receipt_sequences WHERE year = :year FOR UPDATE');
    $stmt->execute([':year' => $year]);
    $last = (int) $stmt->fetchColumn();

    return sprintf('RCP-%04d-%06d', $year, $last);
}

/**
 * Issue a receipt for a verified payment and stamp the rent record.
 *
 * MUST be called inside the same transaction that marks the payment verified.
 *
 * @param array<string,mixed> $record
 * @return array{id:int,receipt_number:string}
 */
function rent_issue_receipt(
    PDO $conn,
    array $record,
    ?int $paymentId,
    string $method,
    ?int $issuedBy
): array {
    $receiptNumber = rent_next_receipt_number($conn);

    $stmt = $conn->prepare(
        "INSERT INTO receipts
            (receipt_number, rent_record_id, payment_id, tenant_id, amount, method, status, issued_by, issued_at)
         VALUES
            (:receipt_number, :rent_record_id, :payment_id, :tenant_id, :amount, :method, 'issued', :issued_by, NOW())"
    );
    $stmt->execute([
        ':receipt_number' => $receiptNumber,
        ':rent_record_id' => (int) $record['id'],
        ':payment_id' => $paymentId,
        ':tenant_id' => (int) $record['tenant_id'],
        ':amount' => $record['amount'],
        ':method' => $method,
        ':issued_by' => $issuedBy,
    ]);
    $receiptId = (int) $conn->lastInsertId();

    $conn->prepare(
        'UPDATE rent_records SET status = :status, payment_method = :method, paid_date = :paid_date,
                receipt_number = :receipt_number
         WHERE id = :id'
    )->execute([
        ':status' => 'Paid',
        ':method' => $method === 'cash' ? 'Cash' : 'EFT',
        ':paid_date' => date('Y-m-d'),
        ':receipt_number' => $receiptNumber,
        ':id' => (int) $record['id'],
    ]);

    return ['id' => $receiptId, 'receipt_number' => $receiptNumber];
}

/**
 * Overdue is derived from the contractual due date, not a background job.
 *
 * @param array<string,mixed> $record
 */
function rent_effective_status(array $record): string
{
    $status = (string) ($record['status'] ?? 'Pending');
    $dueDate = (string) ($record['due_date'] ?? '');

    if (in_array($status, ['Pending', 'Rejected', 'Reversed'], true)
        && $dueDate !== ''
        && $dueDate < date('Y-m-d')) {
        return 'Overdue';
    }

    return $status;
}

/**
 * Arrears position with standard aging buckets.
 *
 * @return array{total_due:float,invoice_count:int,buckets:array<string,float>}
 */
function rent_arrears_for(PDO $conn, int $tenantId): array
{
    $stmt = $conn->prepare(
        "SELECT amount, due_date, status FROM rent_records
         WHERE tenant_id = :tenant_id
           AND status IN ('Pending','Overdue','Submitted','PendingVerification','Rejected','Reversed')"
    );
    $stmt->execute([':tenant_id' => $tenantId]);

    $today = new DateTimeImmutable('today');
    $buckets = ['current' => 0.0, '1_30' => 0.0, '31_60' => 0.0, '61_90' => 0.0, 'over_90' => 0.0];
    $total = 0.0;
    $count = 0;

    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $due = $row['due_date'] ? new DateTimeImmutable((string) $row['due_date']) : $today;

        // Future obligations are scheduled, not in arrears.
        if ($due > $today) {
            continue;
        }

        $amount = (float) $row['amount'];
        $total += $amount;
        $count++;

        $days = (int) $due->diff($today)->days;

        if ($days === 0) {
            $buckets['current'] += $amount;
        } elseif ($days <= 30) {
            $buckets['1_30'] += $amount;
        } elseif ($days <= 60) {
            $buckets['31_60'] += $amount;
        } elseif ($days <= 90) {
            $buckets['61_90'] += $amount;
        } else {
            $buckets['over_90'] += $amount;
        }
    }

    return [
        'total_due' => round($total, 2),
        'invoice_count' => $count,
        'buckets' => array_map(static fn ($value) => round($value, 2), $buckets),
    ];
}
