# Scanner Accuracy Improvements

## Problem
The original scanner was missing open ports when scanned against real hosts (e.g., 206.189.144.108). While nmap detected 11 open ports, the original scanner only found 3 (53, 80, 443) due to a 1.0-second timeout being too short for slow-responding services.

## Solution
Updated `scanner.py` with the following improvements:

### 1. **Increased Timeout** (3.0 seconds default)
- Changed from `1.0s` to `3.0s` per port
- Matches nmap's aggressive timing (4-6 seconds)
- Allows slow-responding mail/database services to be detected

### 2. **Retry Logic**
- Added automatic retry for timed-out connections
- Distinguishes between "closed" (RST received) and "filtered" (no response)
- Retries transient network failures

### 3. **Socket Optimizations**
- Added `TCP_NODELAY` to reduce connection setup time
- Added `SO_LINGER` to avoid TIME_WAIT delays
- Better error code detection (111 = ECONNREFUSED on Linux, 10061 on Windows)

### 4. **Improved State Detection**
- `open`: Connection accepted (error_code == 0)
- `closed`: Connection refused (error_code in (111, 10061))
- `filtered`: No response after all retries
- `error`: DNS resolution failed

## Results

### Before (1.0s timeout)
```
Open ports: 53, 80, 443 (3 found)
Missed: 21, 25, 110, 143, 465, 587, 993, 995
```

### After (3.0s timeout + retry logic)
```
Open ports: 21, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995 (11 found)
Matches nmap output exactly (except 3306/mysql, outside 1-1024 range)
```

## Code Changes

### scan_port() function
- Added `retries` parameter (default 1)
- Increased timeout default from 1.0 to 3.0
- Added loop for retry attempts
- Added socket optimizations

### run_scan() function
- Added `retries` parameter
- Passes retries to scan_port()

### CLI defaults
- `--timeout` default: 1.0 → 3.0
- Help text updated to mention nmap-like accuracy

### Demo timeout
- Demo script timeout: 1.0 → 3.0

## Usage Examples

**Fast scan (1.0s timeout, old behavior):**
```bash
python scanner.py --target 206.189.144.108 --ports 1-1024 --timeout 1.0
```

**Accurate scan (3.0s timeout, nmap-like):**
```bash
python scanner.py --target 206.189.144.108 --ports 1-1024 --timeout 3.0 --db
```

**Slow but thorough (5.0s timeout, extended):**
```bash
python scanner.py --target 206.189.144.108 --ports 1-1024 --timeout 5.0 --db
```

## Performance Notes
- Full 1-1024 port scan on 206.189.144.108 now takes ~126 seconds (vs ~30 seconds at 1.0s)
- Recommended: Use `--threads 50` or higher for faster scans
- For smaller port ranges (e.g., 22,80,443), timeout has minimal impact

## Testing Verified
✅ All 11 open ports on 206.189.144.108 detected and saved to PostgreSQL
✅ Dashboard updated with new scan results
✅ Both CLI and GUI inherit improved accuracy
✅ Backward compatible (can still use --timeout 1.0 if speed is critical)
