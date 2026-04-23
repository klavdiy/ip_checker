# IP ASN Reclassification Feature

## Overview
When the IP checker detects a mismatch between the expected country (from database) and actual country (from geolocation API), it now offers an interactive reclassification workflow. This allows you to update the database based on real-world geolocation data.

## Workflow

### Step 1: Mismatch Detection
When an IP's geolocation doesn't match the ASN's expected country:
```
✗ MISMATCH DETECTED!
  ASN: AS20473 (Kazakhtelecom (AS))
  Expected: KZ (Kazakhstan) | Actual: CN (China)
  Pool: 210.0.0.0/8

⚠ MISMATCH FOUND!
Would you like to reclassify this ASN? (y/n):
```

### Step 2: WHOIS Lookup
If you choose YES (`y`), the system performs a WHOIS query:
```
Step 1: WHOIS Lookup...
  ASN from WHOIS: AS20473
  Country from WHOIS: CN
  Org from WHOIS: Kazakhtelecom
```

### Step 3: Database Update Confirmation
You confirm whether to update the database:
```
Step 2: Update Database
Update database with actual country (CN)? (y/n):
```

### Step 4: Re-Verification
The system reloads the database and re-checks the IP:
```
Step 3: Re-checking IP...

Checking IP: 210.5.4.241
✓ Matches expected location
  ASN: AS20473 (Kazakhtelecom (AS))
  Expected: CN | Actual: CN
  Pool: 210.0.0.0/8
```

### Step 5: Final Report
Success or failure message:

**Success:**
```
============================================================
✓ RE-CHECK SUCCESSFUL
The reclassification has resolved the mismatch.
The IP address is now correctly classified in CN
============================================================
```

**Failure:**
```
============================================================
✗ VERIFICATION COMPLETE
The IP address appears to be incorrectly assigned.
This may indicate IP spoofing or geo-blocking misconfiguration.
============================================================
```

## Usage Modes

### Interactive Mode (default)
```bash
./ip_checker.sh -i 210.5.4.241
```
You'll be prompted for confirmation at each step.

### Auto-Reclassification Mode
Automatically confirms all prompts:
```bash
./ip_checker.sh -i 210.5.4.241 --auto-reclass
```

### Quiet Mode
Suppresses non-essential output:
```bash
./ip_checker.sh -i 210.5.4.241 --quiet
```

### Combined Modes
```bash
./ip_checker.sh -i 210.5.4.241 --auto-reclass --quiet
```

## Database Updates

When you confirm reclassification, the following changes occur in `asn_database.json`:

**Before:**
```json
{
  "asn": "AS20473",
  "expected_country": "KZ",
  "expected_country_name": "Kazakhstan",
  "ip_pools": ["210.0.0.0/8"]
}
```

**After:**
```json
{
  "asn": "AS20473",
  "expected_country": "CN",
  "expected_country_name": "China",
  "ip_pools": ["210.0.0.0/8"]
}
```

## Outcomes

### Outcome 1: "ошибку исключила и все ок"
Reclassification resolved the issue:
- IP now matches the updated expected country
- System confirms with ✓ RE-CHECK SUCCESSFUL message
- Database has been corrected

### Outcome 2: "проверка проведена и адрес неточный"
The IP is genuinely misclassified:
- Even after updating expected_country, IP still doesn't match
- System reports ✗ VERIFICATION COMPLETE
- May indicate IP spoofing or geolocation service error
- Database reflects the actual geolocation

## Examples

### Example 1: Successful Reclassification
```bash
$ ./ip_checker.sh -i 210.5.4.241 --auto-reclass

IP Address Geolocation Checker

Checking IP: 210.5.4.241
✗ MISMATCH DETECTED!
  Expected: KZ | Actual: CN

Auto-reclassification enabled. Proceeding...

Step 1: WHOIS Lookup...
  Country from WHOIS: CN

Step 2: Update Database
Auto-updating database with actual country (CN)...
✓ Database updated successfully

Step 3: Re-checking IP...
✓ Matches expected location
  Expected: CN | Actual: CN

Step 4: Verification Result
============================================================
✓ RE-CHECK SUCCESSFUL
The reclassification has resolved the mismatch.
============================================================

SCAN SUMMARY
Matches (location correct): 1
Mismatches: 0
```

### Example 2: Declining Reclassification
```bash
$ ./ip_checker.sh -i 210.5.4.241

Checking IP: 210.5.4.241
✗ MISMATCH DETECTED!
  Expected: KZ | Actual: CN

Would you like to reclassify this ASN? (y/n): n

Reclassification cancelled

SCAN SUMMARY
Matches: 0
Mismatches: 1
```

## Technical Details

### WHOIS Integration
- Uses system `whois` command
- Parses output for ASN, country code, and organization
- Handles parsing failures gracefully

### API Rate Limiting
- ip-api.com: 45 requests/minute free tier
- Reclassification only makes 1 additional request (re-check)

### Error Handling
- Graceful handling of missing/incomplete WHOIS data
- EOF handling for non-interactive input
- JSON file integrity maintained during updates

## When to Use

✅ **Use reclassification when:**
- You discover ASN geolocation data is outdated
- New IP blocks are being used in different countries
- Geo-blocking needs verification and correction
- Building accurate IP geolocation database

❌ **Don't use when:**
- You want to keep incorrect data intentionally
- Testing IP spoofing detection
- Batch processing (use --auto-reclass instead)

## Notes

- Always verify WHOIS data is correct before confirming updates
- Reclassification updates are permanent in the JSON database
- For reverting changes, edit `asn_database.json` manually or reset from backup
- Consider maintaining database backups before reclassification changes
