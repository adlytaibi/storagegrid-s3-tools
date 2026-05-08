# storagegrid-s3-tools

Command-line tool for executing StorageGRID custom S3 operations (NetApp proprietary extensions).

## Features

- Query bucket usage statistics
- Check consistency settings
- Query metadata notification configuration
- Check last access time settings
- Human-readable formatted output
- Flexible credential management: config file, CLI flags, or interactive prompts
- AWS Signature Version 2 and Version 4 support (v4 by default)

## Requirements

- Python 3.8+
- `requests` library

```bash
pip install requests
```

## Usage

```bash
# Uses credentials from sg_custom_ops.conf alongside the script (default)
python sg_custom_ops.py

# Specify operation
python sg_custom_ops.py -r usage
python sg_custom_ops.py -r consistency
python sg_custom_ops.py -r metadata-notification
python sg_custom_ops.py -r lastaccesstime

# Override endpoint and credentials via CLI
python sg_custom_ops.py -e https://host:10444 -a ACCESS_KEY -s SECRET_KEY

# Use AWS Signature Version 2 (legacy)
python sg_custom_ops.py --sig-version v2

# Use AWS Signature Version 4 with a specific region
python sg_custom_ops.py --sig-version v4 --region us-west-2

# Use a custom config file
python sg_custom_ops.py -c /path/to/config.conf
```

## Configuration

Create `sg_custom_ops.conf` in the same directory as the script:

```ini
[credentials]
endpoint = https://your-storagegrid-host:10444
access_key = YOUR_ACCESS_KEY
secret_key = YOUR_SECRET_KEY
region = us-east-1
```

The `region` field is optional and defaults to `us-east-1`. It is only used with Signature Version 4.

Protect the file:

```bash
chmod 600 sg_custom_ops.conf
```

Credentials are resolved in priority order: **CLI flags → config file → interactive prompt**.

## Example Output

### Usage

```
Endpoint: https://storagegrid.example.com:10444/?x-ntap-sg-usage

Calculated:    2026-05-06T13:36:11.716000Z
Total Objects: 75
Total Size:    272.65 MB (285,897,472 bytes)

Bucket                            Objects         Size
------------------------------------------------------
my-bucket                              75    272.65 MB
```

### Consistency

```
Endpoint: https://storagegrid.example.com:10444/my-bucket?x-ntap-sg-consistency

Consistency: read-after-new-write
```

### Last Access Time

```
Endpoint: https://storagegrid.example.com:10444/my-bucket?x-ntap-sg-lastaccesstime

LastAccessTime: disabled
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Author

Adly Taibi
